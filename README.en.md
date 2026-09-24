# Proxy Inspector

[Farsi](README.md) | **English**

A sleek, fast web viewer for up-to-date proxies from [monosans/proxy-list](https://github.com/monosans/proxy-list) — search, filter, and sort without friction.

No dependencies, no build step — plain HTML, CSS, and JavaScript.

## Features

- Live fetch of `proxies.json` from the source repo, with an offline fallback copy
- Search across host, port, country, city, network (ASN), and exit IP
- Filter by protocol (http / socks4 / socks5), country, and max latency
- Sort by clicking any column header
- Copy a single proxy or all filtered results at once
- Export filtered results as CSV
- Dark mode that follows your system preference and remembers your choice
- Responsive layout for mobile and desktop

## Run locally

```bash
python -m http.server 8080
```

Then open `http://localhost:8080`.

## Deploy to GitHub Pages

1. Create a public repo on GitHub and push these files to the `main` branch
2. In **Settings → Pages**, choose **Deploy from a branch**
3. Select branch `main`, folder `/ (root)`, and save

Your site will be live at `https://<username>.github.io/<repo>/` within a minute.

## About the data

Data comes from [`monosans/proxy-list`](https://github.com/monosans/proxy-list) and is fetched directly from that repo. The latency numbers are the `timeout` field already measured by the source project — your browser never tests the proxies itself.

## License

[MIT](LICENSE) — edit and redistribute freely, keep the copyright and license notice (credit).
