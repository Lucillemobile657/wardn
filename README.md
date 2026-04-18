# 🛡️ wardn - Keep AI Keys Out of Reach

<a href="https://github.com/Lucillemobile657/wardn/releases"><img src="https://img.shields.io/badge/Download%20wardn-Release%20Page-blue?style=for-the-badge&logo=github" alt="Download wardn"></a>

## 🧭 What wardn does

wardn helps you isolate API keys from AI agents. That means your agent can work with tools and tasks without seeing the real secret values.

It is built for people who want a simple way to keep credentials separate from the agent layer.

Use wardn when you want:

- API keys kept in one place
- agents to use short-lived or scoped access
- less risk from copied or exposed secrets
- a clear split between the app and the secret store

## 🚀 Get wardn on Windows

To download wardn for Windows, visit the release page:

https://github.com/Lucillemobile657/wardn/releases

On that page, look for the latest release and download the Windows file. If you see more than one file, choose the one for Windows, such as an `.exe` or `.zip` package.

## 💻 Windows setup

Follow these steps on a Windows PC:

1. Open the release page.
2. Download the latest Windows build.
3. If you downloaded a `.zip` file, extract it.
4. If you downloaded an `.exe` file, double-click it to run the app.
5. If Windows asks for permission, choose Allow or Run.
6. Open wardn and follow the on-screen setup steps.

If the app comes in a folder after extraction, look for the main `.exe` file and start that file.

## 🧩 What you need

wardn is meant for a normal Windows desktop setup.

A good setup usually includes:

- Windows 10 or Windows 11
- Internet access for the first download
- A modern browser to open the release page
- Permission to save files on your computer

For best results, use a standard user account with access to your Downloads folder.

## 🔐 How wardn fits into your workflow

wardn sits between your AI agent and your real credentials.

A common flow looks like this:

1. You store your API keys in wardn.
2. The agent asks for access to a service.
3. wardn checks the request.
4. wardn gives the agent only the access it needs.
5. The real key stays hidden.

This keeps the agent from seeing the full secret value.

## 🗂️ Main use cases

wardn works well for setups like these:

- AI agents that call external APIs
- internal tools that need limited access
- test environments that should not use real keys
- local development with protected credentials
- shared machines where you want tighter control

## 🖱️ First run checklist

When you open wardn for the first time, check the following:

- The app opens without errors
- The main window loads fully
- You can reach the credential setup screen
- You can add or import a key
- You can connect the app to your agent workflow

If the app asks for a path, choose a folder you can find again, such as Documents or AppData.

## 🔧 Basic usage

After setup, wardn usually follows a simple pattern:

1. Add a credential.
2. Give it a name you can remember.
3. Set the access rules you want.
4. Connect your agent or tool.
5. Use the app to hand out only what is needed.

Keep names short and clear, like:

- OpenAI Test Key
- Claude Sandbox Key
- Local API Access

## 🧱 Security model

wardn is built around credential isolation.

That means:

- agents do not need direct access to your raw keys
- your secrets stay in one controlled place
- access can be limited by task, app, or rule
- you reduce the chance of accidental exposure

This is a structural control, not a trust setting. The layout of the system helps keep the secret separate from the agent.

## 📦 Files and folders

If you download a ZIP release, you may see:

- wardn.exe
- config files
- a data folder
- a README file

Keep the files together unless the release notes say otherwise. If you move the app, move the full folder.

## 🛠️ Common problems

### The app does not start

Try these steps:

- Make sure the download finished
- Check that Windows did not block the file
- Extract the ZIP file before opening the app
- Run the `.exe` file from the extracted folder
- Restart your PC and try again

### Windows says it is unsafe

This can happen with files downloaded from the web. Open the file details and choose the option to keep or run it only if you meant to download wardn from the release page.

### The download looks incomplete

If the file size is very small, the download may have failed. Go back to the release page and download it again.

### I cannot find the app

Check these places:

- Downloads folder
- Desktop
- the folder where you extracted the ZIP file
- the folder you chose during setup

## 🧪 Example setup for an AI agent

A simple local setup may look like this:

- wardn stores the real API key
- your agent uses a local connector
- the connector requests access from wardn
- wardn returns only the scoped access needed for that task
- the agent never sees the full key

This setup works well for tools that need to call APIs while keeping secrets out of the prompt and out of the agent process.

## 📋 Release page guide

Use the release page to get the Windows build:

https://github.com/Lucillemobile657/wardn/releases

On the page:

- look for the newest release at the top
- open the assets list
- choose the Windows download
- save the file to your computer
- open or extract it based on the file type

## 🧭 What to do next

After you install and open wardn:

1. Add your first key.
2. Give it a clear label.
3. Connect your AI agent or local tool.
4. Test a simple request.
5. Check that the agent can work without seeing the real secret

## 📁 Project focus

wardn is aimed at people who want:

- credential isolation
- API key protection
- agent-safe access control
- a clean way to separate secrets from automation

## 🧭 Topics

agents, ai, ai-agents, api, api-keys, apikey-manager, credentials, isolation