# TalkUSA Signup Page

A modern, responsive signup page for TalkUSA client accounts (built on MagnusBilling). Ready to deploy on DigitalOcean App Platform.

## Features

- 🎨 Clean, modern UI with gradient design
- 📱 Fully responsive (mobile-friendly)
- 🔒 Secure API integration with MagnusBilling (backend)
- ✅ Client-side form validation
- 🚀 Ready for DigitalOcean App Platform deployment
- ⚡ Fast and lightweight Node.js/Express backend

## Environment Variables

Configure these in your `.env` file (locally) or in DigitalOcean App Platform settings:

| Variable | Description | Example |
|----------|-------------|---------|
| `MAGNUSBILLING_URL` | MagnusBilling API base URL (no trailing slash) | `https://sip.dialerone.net/mbilling` |
| `MAGNUSBILLING_USER_PATH` | Path for user-create endpoint | `/user` (set to empty to use base URL only) |
| `MAGNUSBILLING_API_KEY` | Your MagnusBilling API key | `...` |
| `MAGNUSBILLING_API_SECRET` | Your MagnusBilling API secret | `...` |
| `DEFAULT_GROUP_ID` | Default group ID for new users | `3` |
| `DEFAULT_PLAN_ID` | Default plan ID for new users | `1` |
| `DEFAULT_CALL_LIMIT` | Concurrent call limit for new users | `5` |
| `SMTP2GO_API_KEY` | API key used to send verification emails | `api-...` |
| `SMTP2GO_SENDER` | From address for verification emails | `no-reply@talkusa.net` |
| `EMAIL_VERIFICATION_TTL_MINUTES` | Minutes a verification code stays valid | `10` |
| `PORT` | Server port | `8080` |
| `NODE_ENV` | Environment mode | `production` |
| `DEBUG` | Set to `1` to enable verbose logging | `1` |
| `SESSION_SECRET` | Secret for Express session (required for login) | `change_me` |
| `MB_SIP_MODULE` | Module name for SIP users (varies by instance) | `sip` |
| `MB_CDR_MODULE` | Module name for CDR (varies by instance) | `cdr` |
| `MB_PAGE_SIZE` | Default page size for dashboard API calls | `50` |
| `MAGNUSBILLING_TLS_SERVERNAME` | TLS SNI/verify hostname when calling an IP | e.g. `sip.example.com` |
| `MAGNUSBILLING_TLS_INSECURE` | If `1`, skip TLS verification (testing only) | `1` |
| `MAGNUSBILLING_HOST_HEADER` | Force HTTP Host header (use domain with IP) | e.g. `sip.example.com` |
| `SIP_DOMAIN` | SIP domain to show on success page (defaults to MAGNUSBILLING_TLS_SERVERNAME) | `sip.example.com` |

## Login & Dashboard
- Visit `/login` to sign in with the email/username and password you used at signup.
- After login, `/dashboard` shows three sections and loads data from your MagnusBilling instance via server-to-server API calls using your `MAGNUSBILLING_API_KEY`/`SECRET`.
- Module and filter names can vary between MagnusBilling versions; adjust `MB_SIP_MODULE`/`MB_CDR_MODULE` if needed.

## Local Development

1. Clone this repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Copy `.env.example` to `.env` and configure your settings:
   ```bash
   cp .env.example .env
   ```

4. Edit `.env` with your MagnusBilling credentials

5. Start the development server:
   ```bash
   npm run dev
   ```

6. Open your browser to `http://localhost:8080`

## Deploy to DigitalOcean App Platform

### Method 1: Using GitHub (Recommended)

1. **Push your code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/your-username/your-repo-name.git
   git push -u origin main
   ```

2. **Create App on DigitalOcean:**
   - Go to [DigitalOcean App Platform](https://cloud.digitalocean.com/apps)
   - Click "Create App"
   - Select "GitHub" as your source
   - Authorize DigitalOcean to access your GitHub account
   - Select your repository and branch (main)

3. **Configure the App:**
   - DigitalOcean will auto-detect it as a Node.js app
   - Set the **Run Command** to: `npm start`
   - Set the **HTTP Port** to: `8080`
   - Set the **Build Command** to: `npm install`

4. **Add Environment Variables:**
   Go to the "Environment Variables" section and add:
- `MAGNUSBILLING_URL` = `https://sip.dialerone.net/mbilling/api`
   - `MAGNUSBILLING_API_KEY` = (your API key - mark as SECRET)
   - `MAGNUSBILLING_API_SECRET` = (your API secret - mark as SECRET)
   - `DEFAULT_GROUP_ID` = `3`
   - `DEFAULT_PLAN_ID` = `1`
   - `NODE_ENV` = `production`
   - `PORT` = `8080`

5. **Deploy:**
   - Click "Next" and review your settings
   - Click "Create Resources"
   - Wait for the deployment to complete (usually 2-5 minutes)

### Method 2: Using App Spec YAML

1. Edit `.do/app.yaml` and update the GitHub repository information
2. Use the DigitalOcean CLI or dashboard to create app from spec:
   ```bash
   doctl apps create --spec .do/app.yaml
   ```

## Project Structure

```
magnus/
├── public/
│   └── index.html          # Frontend signup form
├── server.js               # Express backend server
├── package.json            # Node.js dependencies
├── .env                    # Environment variables (local)
├── .env.example            # Environment variables template
├── .gitignore              # Git ignore rules
├── .do/
│   └── app.yaml            # DigitalOcean App Platform config
└── README.md               # This file
```

## API Endpoints

- `GET /` - Serves the signup page
- `POST /api/signup` - Creates a new MagnusBilling user account
- `GET /health` - Health check endpoint for monitoring

## Signup Form Fields

**Required:**
- Username
- Password
- First Name
- Last Name
- Email

**Optional:**
- Phone Number

## Security Notes

- Never commit your `.env` file to Git
- Always use environment variables for sensitive data
- Mark sensitive environment variables as "SECRET" in DigitalOcean
- Use HTTPS in production (automatically provided by DigitalOcean)

## Troubleshooting

### App won't start
- Check that all environment variables are set correctly
- Verify your MagnusBilling API credentials
- Check the application logs in DigitalOcean dashboard

### Signup fails
- Verify the MagnusBilling API URL is correct
- If you get HTTP 404, confirm the final URL in logs and adjust: either move `/api` into `MAGNUSBILLING_URL` or set `MAGNUSBILLING_USER_PATH=/api/user`
- Check API key and secret are valid
- Ensure the group ID and plan ID exist in your MagnusBilling instance
- Enable debug logs by setting `DEBUG=1` and check the server logs for the exact URL and status
- If using an IP over HTTPS and the cert is for a hostname, set `MAGNUSBILLING_TLS_SERVERNAME` to that hostname and (optionally) `MAGNUSBILLING_HOST_HEADER` so Apache/Nginx routes to the correct vhost. Avoid `MAGNUSBILLING_TLS_INSECURE=1` except for temporary tests
- Check application logs for detailed error messages

## Support

For issues related to:
- **This application**: Check the logs and verify configuration
- **MagnusBilling API**: Refer to MagnusBilling documentation
- **DigitalOcean deployment**: Check DigitalOcean App Platform docs

## License

MIT
