import axios from "axios";

axios.defaults.withCredentials = true;
export const traQBaseURL = "https://q.trap.jp/api/v3";
// axios.defaults.baseURL = "http://localhost:8080";
//   process.env.NODE_ENV === "development"
//     ? "http://localhost:3000"
//     : process.env.VUE_APP_API_ENDPOINT;

// NeoShowcase "Soft" member-auth: every page requires login (the router guard
// calls this when /api/users/me is unauthenticated), so bounce to the platform's
// forward-auth login. It forces traQ OIDC; on return the proxy adds
// X-Forwarded-User and /api/users/me succeeds. We no longer drive traQ OAuth
// from the client (that needed a server ClientID we intentionally don't set).
export async function redirectAuthEndpoint(): Promise<void> {
  const redirect = window.location.pathname + window.location.search;
  window.location.assign(`/_oauth/login?redirect=${encodeURIComponent(redirect)}`);
}
