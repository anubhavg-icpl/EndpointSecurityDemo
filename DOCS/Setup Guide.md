# Setup Guide

This guide provides detailed instructions for setting up and running the EndpointSecurityDemo application.

## Prerequisites

Before beginning the setup process, ensure you have the following:

- macOS Catalina 10.15 or later
- Xcode 16 or later (tested with Version 16.2)
- An Apple Developer account with the ability to request special entitlements
- Administrative access to your macOS system

## Entitlement Requirements

EndpointSecurityDemo requires special entitlements from Apple to function properly:

```mermaid
graph TD
    A[Developer Account] -->|Request Entitlement| B[Apple Developer Portal]
    B -->|Grant Entitlement| C[com.apple.developer.endpoint-security.client]
    C -->|Apply to| D[Provisioning Profile]
    D -->|Install in| E[Xcode Project]
    E -->|Build| F[EndpointSecurityDemo.app]
```

### Obtaining the EndpointSecurity Entitlement

1. Log in to your [Apple Developer Account](https://developer.apple.com/account)
2. Request the `com.apple.developer.endpoint-security.client` entitlement by contacting Apple through: [Request System Extension](https://developer.apple.com/contact/request/system-extension/)
3. Provide justification for why your application needs this entitlement
4. Once approved, create a provisioning profile that includes this entitlement
5. Download and install the provisioning profile in your Xcode project

## Building the Project

### Step 1: Configure Xcode Project

1. Open the EndpointSecurityDemo.xcodeproj file in Xcode
2. In the project editor, select the "EndpointSecurityDemo" target
3. Go to the "Signing & Capabilities" tab
4. Select your Team from the dropdown
5. Ensure "Hardened Runtime" is enabled
6. Ensure the `com.apple.developer.endpoint-security.client` entitlement is present

```mermaid
flowchart TD
    A[Open Project] --> B[Select Target]
    B --> C[Go to Signing & Capabilities]
    C --> D[Select Team]
    D --> E[Verify Hardened Runtime]
    E --> F[Verify Entitlements]
    F --> G[Build Project]
```

### Step 2: Build the Project

1. Select the appropriate build configuration (Debug or Release)
2. Choose "My Mac" as the target device
3. Click the "Build" button or use Cmd+B
4. The build produces an app bundle in your build directory

## Running the Application

EndpointSecurityDemo must be run from Terminal with administrative privileges:

```bash
sudo ./EndpointSecurityDemo.app/Contents/MacOS/EndpointSecurityDemo [mode] [verbose]
```

Where `[mode]` is one of:
- `serial` - Uses the serial event processing mode
- `asynchronous` - Uses asynchronous event processing mode
- `gatekeeper` - Runs with enhanced Gatekeeper functionality
- `xprotect` - Runs with enhanced XProtect functionality

The optional `verbose` parameter enables detailed logging.

### System Permissions

The Terminal application must have Full Disk Access permission:

1. Open System Preferences
2. Go to Security & Privacy
3. Select the Privacy tab
4. Select Full Disk Access from the left panel
5. Click the lock icon to make changes (requires admin password)
6. Add Terminal.app to the list of allowed applications

## Verification

To verify that the application is running correctly:

1. Run the application with the `verbose` flag
2. Look for the "Subscribed Events" message in the output
3. Try executing a program like `/usr/bin/top` which should be blocked by default
