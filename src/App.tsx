import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { useAuth } from "./contexts/AuthContext";

// Layouts
import MainLayout from "./layouts/MainLayout";
import AuthLayout from "./layouts/AuthLayout";

// Pages
import LoginPage from "./pages/LoginPage";
import RoleSelectionPage from "./pages/RoleSelectionPage";
import RegisterPage from "./pages/RegisterPage";
import MaintenancePage from "./pages/MaintenancePage";
import ClientHomePage from "./pages/client/ClientHomePage";
import ProfessionalsPage from "./pages/client/ProfessionalsPage";
import ProfessionalHomePage from "./pages/professional/ProfessionalHomePage";
import RegisterConsultationPage from "./pages/professional/RegisterConsultationPage";
import SchedulingPage from "./pages/professional/SchedulingPage";
import PrivatePatientsPage from "./pages/professional/PrivatePatientsPage";
import MedicalRecordsPage from "./pages/professional/MedicalRecordsPage";
import DocumentsPage from "./pages/professional/DocumentsPage";
import ProfessionalReportsPage from "./pages/professional/ProfessionalReportsPage";
import ProfessionalProfilePage from "./pages/professional/ProfessionalProfilePage";
import AdminHomePage from "./pages/admin/AdminHomePage";
import ManageUsersPage from "./pages/admin/ManageUsersPage";
import ManageServicesPage from "./pages/admin/ManageServicesPage";
import ManageSchedulingAccessPage from "./pages/admin/ManageSchedulingAccessPage";
import ReportsPage from "./pages/admin/ReportsPage";

// Route guards
const ProtectedRoute = ({
  children,
  allowedRoles,
}: {
  children: React.ReactNode;
  allowedRoles: string[];
}) => {
  const { user, isAuthenticated } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  if (
    allowedRoles.length > 0 &&
    user &&
    !allowedRoles.includes(user.currentRole || "")
  ) {
    // Redirect to appropriate home page based on current role
    if (user.currentRole === "client") {
      return <Navigate to="/client" replace />;
    } else if (user.currentRole === "professional") {
      return <Navigate to="/professional" replace />;
    } else if (user.currentRole === "admin") {
      return <Navigate to="/admin" replace />;
    }
  }

  return <>{children}</>;
};

function App() {
  const { user, isAuthenticated, isLoading } = useAuth();

  // Show loading while checking authentication
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Carregando...</p>
        </div>
      </div>
    );
  }

  return (
    <Routes>
      {/* 🔧 MAINTENANCE ROUTE - ACCESSIBLE WITHOUT LOGIN */}
      <Route path="/manutencao" element={<MaintenancePage />} />
      
      {/* 🔥 ROOT ROUTE - SEMPRE LOGIN */}
      <Route path="/" element={<LoginPage />} />

      {/* Auth routes */}
      <Route element={<AuthLayout />}>
        <Route path="/select-role" element={<RoleSelectionPage />} />
        <Route path="/register" element={<RegisterPage />} />
      </Route>

      {/* Client routes */}
      <Route
        element={
          <ProtectedRoute allowedRoles={["client"]}>
            <MainLayout />
          </ProtectedRoute>
        }
      >
        <Route path="/client" element={<ClientHomePage />} />
        <Route path="/client/professionals" element={<ProfessionalsPage />} />
      </Route>

      {/* Professional routes */}
      <Route
        element={
          <ProtectedRoute allowedRoles={["professional"]}>
            <MainLayout />
          </ProtectedRoute>
        }
      >
        <Route path="/professional" element={<ProfessionalHomePage />} />
        <Route path="/professional/scheduling" element={<SchedulingPage />} />
        <Route path="/professional/private-patients" element={<PrivatePatientsPage />} />
        <Route path="/professional/medical-records" element={<MedicalRecordsPage />} />
        <Route path="/professional/documents" element={<DocumentsPage />} />
        <Route path="/professional/reports" element={<ProfessionalReportsPage />} />
        <Route path="/professional/profile" element={<ProfessionalProfilePage />} />
        <Route
          path="/professional/register-consultation"
          element={<RegisterConsultationPage />}
        />
      </Route>

      {/* Admin routes */}
      <Route
        element={
          <ProtectedRoute allowedRoles={["admin"]}>
            <MainLayout />
          </ProtectedRoute>
        }
      >
        <Route path="/admin" element={<AdminHomePage />} />
        <Route path="/admin/users" element={<ManageUsersPage />} />
        <Route path="/admin/services" element={<ManageServicesPage />} />
        <Route path="/admin/scheduling-access" element={<ManageSchedulingAccessPage />} />
        <Route path="/admin/reports" element={<ReportsPage />} />
      </Route>

      {/* 🔥 CATCH-ALL - QUALQUER ROTA DESCONHECIDA VAI PARA LOGIN */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;