import React from "react";

import HomePage from "../public/HomePage.jsx";
import PricingPage from "../public/PricingPage.jsx";
import TermsPage from "../public/TermsPage.jsx";
import PrivacyPage from "../public/PrivacyPage.jsx";
import RefundPolicyPage from "../public/RefundPolicyPage.jsx";
import AboutPage from "../public/AboutPage.jsx";
import FeaturesPage from "../public/FeaturesPage.jsx";
import ContactPage from "../public/ContactPage.jsx";

export default function MarketingApp() {
  const pathName = window.location.pathname || "";
  const cleanPath = pathName.replace(/\/+$/, "") || "/";

  if (cleanPath === "/pricing") return <PricingPage />;
  if (cleanPath === "/terms") return <TermsPage />;
  if (cleanPath === "/privacy") return <PrivacyPage />;
  if (cleanPath === "/refunds") return <RefundPolicyPage />;
  if (cleanPath === "/about") return <AboutPage />;
  if (cleanPath === "/features") return <FeaturesPage />;
  if (cleanPath === "/contact") return <ContactPage />;

  return <HomePage />;
}