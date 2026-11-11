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
| Bundle ID `sa.hasadco.hr`, display name "Hassad Team" | `capacitor.config.json` |
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
2. Platform **iOS**, name **Hassad Team** (Arabic subtitle/localized name
   e.g. "حصاد للموظفين"), primary language, bundle ID `sa.hasadco.hr`, and any SKU
   (e.g. `hassad-team`). Category: **Business**. This sits next to the
   existing customer app (محمصة حصاد, Food & Drink) under the same account.
   The description should say it's for Hassad staff so Apple doesn't see it as
   a duplicate of the customer app (guideline 4.3).
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

In App Store Connect, under **Pricing and Availability**, choose
**Public**: anyone can download Hassad from the App Store, and only staff
that HR has added can log in. Plenty of companies publish their employee
apps this way.

Apple does sometimes question single-company apps (business guidelines,
section 3.2) or apps that look like a website in a wrapper (4.2, "minimum
functionality"). To get through review the first time:

- **App Review notes**: say plainly that this is Hassad Coffee Roasters'
  employee app, that HR issues accounts (invite-only), and that staff install it
  on their personal phones, which is why it's on the public store.
- **Demo account**: give a working login that shows real-looking data
  (attendance, leave, payslips, counts). An empty account invites rejection.
- **Description and screenshots**: show the native features (clock-in with
  location, receipt camera scan), not just forms.
- **Seller name**: the store shows the developer account's name. If the
  account was enrolled as an individual, your personal name appears instead of
  "Hassad". Showing the company name needs an Organization account, which
  requires a D-U-N-S number.

If Apple still rejects it under 3.2, the fallbacks are:

- **Private (Custom App)**: same build, set to *"Private availability"*, and
  staff install it through Apple Business Manager.
- **TestFlight**: up to 10,000 testers, but builds expire after 90 days.

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
