# Gmail setup (one-time, about 5 minutes)

During early access, Gmail users connect the tool through **their own** Google app. It is free, it stays
in your Google account, and only you use it. Outlook needs no setup.

## 1. Create the Google app

1. Open <https://console.cloud.google.com/> with the Google account whose Gmail you want to clean up.
2. **Create a project** (any name, e.g. "mail-unsubscriber").
3. **APIs & Services → Library →** search **Gmail API → Enable**.
4. **Google Auth Platform → Get started**:
   - App name: anything (e.g. "My mail-unsubscriber"); support email: yours.
   - Audience: **External**; contact email: yours; agree and **Create**.
5. **Data Access → Add or remove scopes →** paste
   `https://www.googleapis.com/auth/gmail.metadata` → **Add to table → Update → Save**.
   (Headers and labels only. Google itself blocks message bodies for this permission.)
6. **Audience → Test users → Add users →** add your own Gmail address → **Save**.
7. **Clients → Create client →** type **Desktop app** → **Create**. Copy the **Client ID** and **Client secret**.

## 2. Tell the tool about it

Add to your shell profile (`~/.zshrc`), then open a new Terminal:

```sh
export MAIL_UNSUB_GOOGLE_CLIENT_ID="1234-abc.apps.googleusercontent.com"
export MAIL_UNSUB_GOOGLE_CLIENT_SECRET="your-client-secret"
```

Then sign in:

```sh
unsub login --provider gmail
```

Google shows "Google hasn't verified this app": that is your own app, choose **Continue**.

## Good to know

- **Sign in again every 7 days.** Google expires sign-ins for apps in "Testing" mode after 7 days;
  `unsub` tells you when (`unsub login --provider gmail`).
- The client secret identifies your app; it does not grant access to anyone's mail by itself. Still,
  keep it out of public places.
- To remove access: <https://myaccount.google.com/permissions>, or `unsub logout --account gmail --purge`.
