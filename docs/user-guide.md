# AutonomAuth User Guide

## Introduction

AutonomAuth is a decentralized authentication system that gives you full control over your identity and authentication data. Your data is stored securely on the Autonomi network, not on centralized servers, ensuring privacy and security.

This guide will help you understand how to use AutonomAuth for authentication across multiple websites and services.

## Getting Started

### Download the Mobile App

1. Download the AutonomAuth mobile app from the [App Store](#) (iOS) or [Google Play](#) (Android).
2. Install the app on your device.

### Create Your Identity

1. Open the AutonomAuth app.
2. Tap "Create New Identity".
3. Follow the prompts to create your master key - this will be the foundation of your digital identity.
4. Write down your recovery phrase in a safe, offline location. This is critical for recovering your identity if you lose your device.
5. Set up a PIN or use your device's biometric authentication (fingerprint/face recognition) to secure the app.

### Create Your First Profile

1. Once your identity is created, you'll be prompted to create a profile.
2. Enter a name for your profile (e.g., "Personal", "Work", "Social Media").
3. Optionally, add a profile picture.
4. Tap "Create Profile".

You can create multiple profiles for different purposes. Each profile acts as a separate identity that you can use for different services.

## Authenticating with Websites

### First-time Authentication

1. When visiting a website that supports AutonomAuth, click the "Sign in with AutonomAuth" button.
2. The website will display a QR code.
3. Open the AutonomAuth app on your phone.
4. Tap "Scan QR Code" and scan the QR code displayed on the website.
5. Review the authentication request, which will show:
   - The website name
   - The requested permissions
   - The profile you'll use for authentication
6. Select which profile you want to use for this website.
7. Tap "Approve" to authenticate.
8. The website will automatically log you in.

### Return Visits

1. When returning to a website you've previously authenticated with:
2. Click "Sign in with AutonomAuth".
3. Scan the QR code with your app.
4. Since you've already authorized this website with your profile, you'll see a simplified verification screen.
5. Confirm the authentication to log in.

### Push Authentication

For websites that support push authentication:

1. Click "Sign in with AutonomAuth" on the website.
2. You'll receive a push notification on your phone.
3. Open the notification to review the authentication request.
4. Tap "Approve" to authenticate without needing to scan a QR code.

## Managing Your Profiles

### Creating Additional Profiles

1. In the AutonomAuth app, tap the profile icon in the bottom navigation.
2. Tap "Create New Profile".
3. Enter a name and customize the profile as desired.
4. Tap "Create Profile".

### Editing Profiles

1. In the Profiles section, select the profile you want to edit.
2. Tap the "Edit" button.
3. Update the profile name, picture, or other details.
4. Tap "Save".

### Setting a Default Profile

1. In the Profiles section, select the profile you want to make default.
2. Tap the "⋮" menu.
3. Select "Set as Default".

The default profile will be pre-selected when authenticating with new websites.

## Managing Website Connections

### Viewing Connected Sites

1. In the AutonomAuth app, tap the "Connections" tab.
2. You'll see a list of all websites you've authenticated with.
3. Tap on any website to see details about your connection.

### Revoking Access

1. In the Connections tab, tap the website you want to disconnect from.
2. Tap "Revoke Access".
3. Confirm your decision.

The website will no longer be able to authenticate using your profile. You'll need to go through the first-time authentication process again if you want to reconnect.

## Security Features

### Social Recovery

If you lose access to your device, you can recover your identity using social recovery:

1. Download the AutonomAuth app on your new device.
2. Tap "Restore Identity".
3. Select "Social Recovery".
4. Follow the prompts to contact your designated recovery guardians.
5. Once enough guardians have approved your recovery request, your identity will be restored.

### Setting Up Social Recovery

1. In the app, go to Settings > Security > Social Recovery.
2. Tap "Set Up Social Recovery".
3. Choose trusted contacts to be your recovery guardians.
4. Specify how many guardians (threshold) are needed to recover your account.
5. Send invitations to your guardians.
6. Once they accept, your social recovery setup is complete.

### WebAuthn Integration

For enhanced security, you can link your AutonomAuth profile with WebAuthn-compatible hardware security keys:

1. Go to Settings > Security > WebAuthn.
2. Tap "Add Security Key".
3. Follow the prompts to register your security key.
4. Once registered, you can use your security key as an additional authentication factor.

## Privacy Features

### Selective Disclosure

AutonomAuth allows you to share only the information that websites need:

1. When authenticating with a website that requests additional information (e.g., email, name):
2. Review the requested information in the authorization screen.
3. Toggle off any information you don't want to share.
4. Tap "Approve" to authenticate with only the selected information shared.

### Creating Attestations

For verified information that you want to be able to share:

1. Go to Settings > Privacy > Attestations.
2. Tap "Create New Attestation".
3. Select the type of information (e.g., "Email Verification").
4. Enter the information and verify it as prompted.
5. Once verified, the attestation will be available to share with websites when requested.

## Troubleshooting

### Authentication Failures

If authentication fails:

1. Make sure your internet connection is stable.
2. Check that the QR code is fully visible and properly lit.
3. Ensure your app is up to date.
4. Try refreshing the QR code on the website.
5. If problems persist, contact support from the Help section of the app.

### App Not Receiving Push Notifications

If you're not receiving push notifications:

1. Go to your device settings and ensure notifications are enabled for the AutonomAuth app.
2. Check that background app refresh is enabled for the app.
3. Verify that you have a stable internet connection.
4. In the app, go to Settings > Notifications and ensure push notifications are enabled.

## Support

For additional help, you can:

- Visit the [Help Center](#) in the app
- Email support at [support@autonomauth.com](#)
- Visit our [Support Website](#) for FAQs and tutorials

---

Thank you for using AutonomAuth! By controlling your own authentication data on the Autonomi network, you're taking an important step toward digital sovereignty and privacy.
