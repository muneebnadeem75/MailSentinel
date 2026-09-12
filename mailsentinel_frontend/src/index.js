import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { GoogleOAuthProvider } from "@react-oauth/google";

const root = ReactDOM.createRoot(document.getElementById("root"));

root.render(
  <GoogleOAuthProvider clientId="571367355969-srm13g8a4ngf5uqmbm2i67b8ssgjjb57.apps.googleusercontent.com">
    <App />
  </GoogleOAuthProvider>
);