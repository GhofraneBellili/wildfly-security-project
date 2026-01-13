# Integration Plan: Replace Supabase Auth with Phoenix IAM

## Tasks
- [x] Update AuthContext.tsx to use IAM OAuth2 client instead of Supabase
- [x] Modify Auth.tsx component to initiate IAM login flow
- [x] Add callback handling for OAuth2 redirect
- [x] Update profile type to match IAM UserProfile
- [x] Remove Supabase configuration check from main.tsx
- [ ] Test the integration by running the app and IAM server

## Notes
- The oauth2Client.ts is already implemented for IAM OAuth2 PKCE flow.
- Ensure IAM server is running on the configured URL.
- Handle token refresh and logout properly.
- For now, all authenticated users are directed to the Marketplace component since role information isn't provided by IAM JWT.
