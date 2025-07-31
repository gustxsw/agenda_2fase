import React from 'react';
import { Outlet, Navigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

const AuthLayout: React.FC = () => {
  const { isAuthenticated, user } = useAuth();
  
  // If authenticated, redirect to appropriate home page
  if (isAuthenticated && user) {
    if (user.currentRole === 'client') {
      return <Navigate to="/client" replace />;
    } else if (user.currentRole === 'professional') {
      return <Navigate to="/professional" replace />;
    } else if (user.currentRole === 'admin') {
      return <Navigate to="/admin" replace />;
    }
  }
  
  return (
    <div className="min-h-screen">
      <Outlet />
    </div>
  );
};

export default AuthLayout;