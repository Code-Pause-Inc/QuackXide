import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { brand } from "./config/brand";
import "./index.css";

document.title = brand.publicName;

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
