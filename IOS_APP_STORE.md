# Shipping Hassad to the App Store (iOS)

The iOS app is a [Capacitor](https://capacitorjs.com) wrapper around the same
`index.html` that GitHub Pages serves. The web files are **bundled inside the
app**, not loaded from `app.hasadco.sa`. It talks to the same Supabase project,
so data, logins and RLS are identical to the web app.

```
index.html, tailwind.css, logo.png, …   ← source of truth (repo root)
        │  npm run www
        ▼
www/                                     ← generated, git-ignored
        │  npx cap sync ios
        ▼
ios/App/App/public/                      ← generated, git-ignored, shipped in the .ipa
```

Already set up in this repo:

| What | Where |
|---|---|
| Bundle ID `sa.hasadco.hr`, display name "Hassad" | `capacitor.config.json` |
| Xcode project (Swift Package Manager, no CocoaPods) | `ios/` |
| Camera, photo library and location permission texts (the app crashes without them) | `ios/App/App/Info.plist` |
| "No non-exempt encryption" flag (skips the export-compliance question on each upload) | `ios/App/App/Info.plist` |
| 1024×1024 opaque app icon and cream splash screen, made from `logo.png` | `ios/App/App/Assets.xcassets/` |

---

## 1. One-time setup on a Mac

You need a Mac with **Xcode 26 or newer** (from the Mac App Store) and Node 22+.

```bash
git clone https://github.com/omarkhalawi21/HUMAN-RESOURCE-APP.git
```

```bash
cd HUMAN-RESOURCE-APP
```

```bash
npm install
```

```bash
npm run ios:sync
```

```bash
npm run ios:open
```

In Xcode, select the **App** target, open **Signing & Capabilities**, set
**Team** to your Apple Developer team, and leave "Automatically manage
signing" on. The bundle identifier should read `sa.hasadco.hr`. If Apple says
it is taken, change it to something like `sa.hasadco.hassadhr` in both Xcode
and `capacitor.config.json`.

Plug in an iPhone (or pick a simulator) and press ▶ Run. Then go through the
test list in section 4 before uploading.

## 2. Create the app in App Store Connect

1. Open [App Store Connect](https://appstoreconnect.apple.com) and go to **Apps → + → New App**.
2. Platform **iOS**, name **Hassad** (or "Hassad HR"; names must be unique on
   the store), primary language, bundle ID `sa.hasadco.hr`, and any SKU (e.g. `hassad-hr`).
3. **App Privacy**: declare what the app collects. The app collects name, email,
   phone, precise location (clock-in), photos (receipts/maintenance) and
   employment data, all linked to the user and used for "App Functionality",
   with no tracking. Use the **Privacy Policy URL** of a public page with the
   content of `PRIVACY_NOTICE.md` (required).
4. **App Review Information**: give a **demo login** (an employee account with
   sample data at a demo branch). Reviewers can't sign up because sign-up is
   invite-only. Without a working demo login the app is rejected.

## 3. Upload a build

In Xcode, set the device to **Any iOS Device (arm64)**, then choose
**Product → Archive**. When the Organizer opens, choose
**Distribute App → App Store Connect → Upload**.

After about 10–30 minutes of processing, the build appears in App Store Connect
under **TestFlight**. Install it on your own phone through the TestFlight app
first.

### Choose how it is distributed

In App Store Connect, under **Pricing and Availability**:

- **Private (recommended for an employee-only app)**: choose *"Private
  availability"* / Custom App and enter Hassad's Apple Business Manager
  organization ID. Staff then get the app through Apple Business Manager or a
  redemption code. Apple's guideline 3.2 says apps built for one company's
  employees should go this way. On the public store they are often rejected.
  Apple Business Manager is free, but Hassad needs a D-U-N-S number to enroll.
- **Public**: anyone can find it, but only invited staff can log in. Expect
  reviewers to question it under guideline 3.2 or 4.2 ("minimum functionality").
- **TestFlight only**: up to 10,000 testers by email or public link, with no
  full review for internal testers. Builds expire after 90 days.

Then **Submit for Review**.

## 4. Things to test on a real iPhone before submitting

The web app was written for browsers. These parts behave differently inside an
iOS app's web view and need a manual check:

- [ ] Log in, log out, password reset (the reset email link opens in Safari,
      on the website. That is fine.)
- [ ] Clock in with location: the iOS permission prompt appears and shows the text above
- [ ] Receipt and maintenance photo upload: the camera and library open
- [ ] **CSV / JSON exports** (attendance, counts, bakery, admin snapshot)
      use `<a download>`. They may do nothing inside the app.
- [ ] **Print / "open in new window" views** (payslips, reports, documents)
      use `window.open('')`, which an iOS web view usually blocks.
- [ ] Phone notch / home bar: nothing important hidden under them
- [ ] Web Push notifications **won't work** in the app (Apple only allows
      native push, through APNs). Staff who rely on notifications can keep
      using the Home Screen web app, or native push can be added later with
      `@capacitor/push-notifications`.

If exports or print views fail, they can be routed through the
`@capacitor/share` / `@capacitor/filesystem` plugins. That is a follow-up
code change.

## 5. Apple review requirements to clear

- **In-app account deletion (guideline 5.1.1(v))**: accounts are created
  in the app (invite-only sign-up), so Apple requires a way to *start* account
  deletion from inside the app. For an HR app, a "Request account deletion"
  button that notifies HR is acceptable, as long as the app says what is kept
  for legal retention and why. **This doesn't exist yet. Add it before the first
  submission.**
- **Demo account** for the reviewer (see step 2).
- **Privacy policy URL** (see step 2).

## 6. Shipping updates

The web files are bundled, so **a change to `index.html` reaches iPhone users
only after a new App Store build**. GitHub Pages still updates instantly for
browser and Home Screen users. To ship an update to iOS:

```bash
git pull
```

```bash
npm run ios:sync
```

Then, in Xcode, raise **Build** (and **Version** for user-visible
releases), choose **Product → Archive**, and upload. SQL migrations in
`supabase-rls.sql` are shared by web and iOS. Run them before releasing either.
