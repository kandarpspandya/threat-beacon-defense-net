
import { createRoot } from 'react-dom/client'
import App from './App.tsx'
import './index.css'

const root = document.getElementById("root");

if (root) {
  console.log("Main: Rendering App component to root element");
  createRoot(root).render(<App />);
} else {
  console.error("Root element not found");
}
