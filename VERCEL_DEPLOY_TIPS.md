# Changes work locally but not on Vercel

## About the build log

The lines **"npm install -g serve"** and **"serve -s build"** in the log are **not** commands Vercel runs. They are a **message from Create React App** at the end of `npm run build` (see https://cra.link/deployment). You can ignore them.

Vercel only runs your **build script** (`npm run build`), then serves the `build` folder. No need to add or run `serve` anywhere.

---

Follow these in order.

---

## 1. Push your changes to the branch Vercel uses

Vercel only rebuilds when you push. It usually deploys from **main** (or **master**).

```bash
git status
git add -A
git commit -m "Describe your changes"
git push origin main
```

If your default branch has another name, use that (e.g. `git push origin master`).

---

## 2. Confirm Vercel is using the right branch

1. Open [vercel.com](https://vercel.com) → your project.
2. **Settings** → **Git**.
3. Under **Production Branch**, note the branch name (often `main`).
4. Your latest commit must be on that branch (from step 1).

---

## 3. Redeploy and clear build cache

Sometimes Vercel serves an old build or uses a cached build.

1. In the project, go to the **Deployments** tab.
2. Open the **⋯** menu on the latest deployment.
3. Click **Redeploy**.
4. Turn **on** “Clear build cache and redeploy”.
5. Click **Redeploy**.

Wait for the build to finish (Build and Deployment logs should show success).

---

## 4. Hard refresh the site

After a new deployment, your browser or CDN might still show the old version.

- **Windows/Linux:** `Ctrl + Shift + R`
- **Mac:** `Cmd + Shift + R`

Or open the site in an **Incognito/Private** window.

---

## If it still doesn’t update

- In **Deployments**, open the latest deployment and check the **Building** log. If the build failed, fix the reported error (often a missing env var or a failing `npm run build`).
- In **Settings** → **General**, check **Root Directory**. For this repo it should be **empty** (root of the repo). If it’s set to `frontend`, the root `vercel.json` may be ignored; the app can still work, but the build runs from `frontend/` and you must push changes and redeploy as above.
