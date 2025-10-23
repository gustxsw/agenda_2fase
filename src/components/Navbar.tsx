import React from "react";
import { useAuth } from "../contexts/AuthContext";
import { Link } from "react-router-dom";
import { LogOut, User, Menu } from "lucide-react";
import RoleSwitcher from "./RoleSwitcher";

type NavbarProps = {
  onMenuClick: () => void;
};

const Navbar: React.FC<NavbarProps> = ({ onMenuClick }) => {
  const { user, logout } = useAuth();

  const handleLogout = async () => {
    try {
      await logout();
    } catch (error) {
      console.error("Logout error:", error);
    }
  };

  return (
    <nav className="navbar bg-white text-gray-800 shadow-lg border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-24 items-center">
          <div className="flex items-center">
            <button
              onClick={onMenuClick}
              className="md:hidden p-2 rounded-md hover:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-red-500"
            >
              <Menu className="h-6 w-6 text-gray-600" />
            </button>

            {/* Logo sem link - não clicável */}
            <div className="ml-2 md:ml-0">
              <img
                src="/logo_quiroferreira.svg"
                alt="Logo Quiro Ferreira"
                className="h-24 w-auto"
                style={{ maxHeight: "100px" }}
              />
            </div>
          </div>

          <div className="flex items-center space-x-4">
            {user && (
              <>
                {/* Role Switcher */}
                <RoleSwitcher />

                {/* User Info */}
                <div className="hidden sm:flex items-center mr-4">
                  <User className="h-5 w-5 mr-2 text-gray-600" />
                  <span className="font-medium text-gray-800">{user.name}</span>
                </div>

                {/* Logout Button */}
                <button
                  onClick={handleLogout}
                  className="flex items-center text-gray-600 hover:text-red-600 focus:outline-none transition-colors duration-200"
                  title="Sair"
                >
                  <LogOut className="h-5 w-5" />
                  <span className="ml-1 hidden sm:inline">Sair</span>
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;