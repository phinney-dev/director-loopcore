# director.loopcore.work

Static site for the General Director of Loopcore Enterprises. No build step.

- `index.html` is the whole site
- `assets/phinius-njeru.jpg` is the portrait

## Deploy

1. Create a GitHub repo and push this folder.
2. Cloudflare dashboard > Workers & Pages > Create > Pages > Connect to Git, pick the repo.
   Framework preset: None. Build command: leave empty. Output directory: `/`.
3. After the first deploy, open the project > Custom domains > Set up a custom domain > `director.loopcore.work`.
   Cloudflare adds the CNAME automatically if loopcore.work DNS is on Cloudflare.
