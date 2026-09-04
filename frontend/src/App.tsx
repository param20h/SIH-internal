import { Route, Routes } from "react-router-dom";

import { Nav } from "./components/layout/Nav";
import AnalysesListPage from "./pages/AnalysesListPage";
import AnalysisPage from "./pages/AnalysisPage";
import DashboardPage from "./pages/DashboardPage";
import UploadPage from "./pages/UploadPage";

export default function App() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Nav />
      <main>
        <Routes>
          <Route path="/" element={<UploadPage />} />
          <Route path="/analyses" element={<AnalysesListPage />} />
          <Route path="/analyses/:id" element={<AnalysisPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
        </Routes>
      </main>
    </div>
  );
}
