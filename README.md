# HR App

A clean, single-file employee management web app focused on attendance and HR essentials. Inspired by [Availo](https://availo.app) (branding, attendance focus) and [Foodics](https://foodics.com) (console UI).

## Features

- Attendance — daily clock-in / clock-out with automatic late detection and optional location capture
- Employee directory — add, edit, search, and filter employees by department
- Leave requests — submit requests, manager approve/reject, balance tracking
- Payroll — monthly run, payslip history, export to CSV
- Admin dashboard — live stats, 7-day attendance chart, department breakdown, activity feed
- Reports — date-ranged attendance, leave, and payroll summaries
- Bilingual — English and العربية with full RTL support
- Multi-role auth — admin and employee accounts

## How to run

It's one HTML file. Two ways to use it:

**Locally** — just open `index.html` in any modern browser. That's it.

**Hosted** — push this repo to GitHub and enable GitHub Pages (Settings → Pages → Deploy from branch → main → root). Your live URL will be at `https://<your-username>.github.io/hr-app/`.

## Demo accounts

The app seeds itself with sample data on first load — 8 employees, ~100 attendance records, sample leave and payroll cycles.

| Username | Password | Role |
|----------|----------|------|
| `admin`  | `admin123`  | Admin |
| `sara`   | `sara123`   | Admin (HR Manager) |
| `khaled` | `khaled123` | Employee |
| `layla`  | `layla123`  | Employee |

## Tech

Plain HTML + CSS + vanilla JavaScript. Tailwind via CDN. Persistence via `localStorage` — no backend yet. Suitable for a single user / demo / small team that all use the same device.

## Roadmap

- Real backend (Node + database) for true multi-user support
- Webcam selfie verification on clock-in
- Calendar export for leave (.ics)
- Payslip PDF generation
- Email notifications on leave approval
- Mobile app

## License

MIT — do whatever you'd like with it.
