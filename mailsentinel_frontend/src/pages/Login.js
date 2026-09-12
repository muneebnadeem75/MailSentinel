import React from "react";
import "../styles/login.css";

function Login() {

  return (
    <div className="hero">

      <div className="heroContent">
        <h1 className="mainTitle">
          STOP <span>PHISHING</span> DEAD
        </h1>

        <p className="subText">
          MailSentinel connects to your Gmail and performs deep analysis
          on suspicious emails exposing spoofed senders, malicious links,
          and phishing tactics before they reach you.
        </p>

        <div className="btnGroup">
          <button 
            className="primaryBtn" 
              onClick={() => window.location.href = "http://127.0.0.1:8000/auth/google/"}
            >
      Connect with Google
</button>
        </div>
      </div>

    </div>
  );
}

export default Login;