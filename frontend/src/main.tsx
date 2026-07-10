import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import './index.css';
import App from './App.tsx';
import Dashboard from './pages/Dashboard.tsx';
import ScanDetail from './pages/ScanDetail.tsx';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<App />}>
          <Route index element={<Dashboard />} />
          <Route path="scans/:id" element={<ScanDetail />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
);
