import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { ChevronDown, User, Shield, Briefcase, RefreshCw } from 'lucide-react';

const RoleSwitcher: React.FC = () => {
  const { user, switchRole } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  if (!user || !user.currentRole) return null;

  // If user has only one role, don't show the switcher
  const userRoles = JSON.parse(localStorage.getItem('user') || '{}').roles || [];
  if (userRoles.length <= 1) return null;

  const handleRoleSwitch = async (role: string) => {
    if (role === user.currentRole) {
      setIsOpen(false);
      return;
    }

    try {
      setIsLoading(true);
      await switchRole(role);
      setIsOpen(false);
    } catch (error) {
      console.error('Error switching role:', error);
    } finally {
      setIsLoading(false);
    }
  };

  const getRoleInfo = (role: string) => {
    switch (role) {
      case 'client':
        return {
          title: 'Cliente',
          icon: <User className="h-4 w-4" />,
          color: 'text-green-600',
          bgColor: 'bg-green-50'
        };
      case 'professional':
        return {
          title: 'Profissional',
          icon: <Briefcase className="h-4 w-4" />,
          color: 'text-blue-600',
          bgColor: 'bg-blue-50'
        };
      case 'admin':
        return {
          title: 'Administrador',
          icon: <Shield className="h-4 w-4" />,
          color: 'text-red-600',
          bgColor: 'bg-red-50'
        };
      default:
        return {
          title: role,
          icon: <User className="h-4 w-4" />,
          color: 'text-gray-600',
          bgColor: 'bg-gray-50'
        };
    }
  };

  const currentRoleInfo = getRoleInfo(user.currentRole);

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        disabled={isLoading}
        className={`
          flex items-center space-x-2 px-3 py-2 rounded-lg transition-colors
          ${currentRoleInfo.bgColor} ${currentRoleInfo.color}
          hover:opacity-80 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500
          ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}
        `}
      >
        {isLoading ? (
          <RefreshCw className="h-4 w-4 animate-spin" />
        ) : (
          currentRoleInfo.icon
        )}
        <span className="text-sm font-medium hidden sm:inline">
          {currentRoleInfo.title}
        </span>
        <ChevronDown className={`h-4 w-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      {isOpen && (
        <>
          {/* Backdrop */}
          <div
            className="fixed inset-0 z-10"
            onClick={() => setIsOpen(false)}
          />
          
          {/* Dropdown */}
          <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border border-gray-200 z-20">
            <div className="py-1">
              <div className="px-3 py-2 text-xs font-medium text-gray-500 uppercase tracking-wider border-b border-gray-100">
                Alternar Acesso
              </div>
              {userRoles.map((role: string) => {
                const roleInfo = getRoleInfo(role);
                const isCurrentRole = role === user.currentRole;
                
                return (
                  <button
                    key={role}
                    onClick={() => handleRoleSwitch(role)}
                    disabled={isLoading || isCurrentRole}
                    className={`
                      w-full flex items-center space-x-3 px-3 py-2 text-sm transition-colors
                      ${isCurrentRole 
                        ? `${roleInfo.bgColor} ${roleInfo.color} font-medium` 
                        : 'text-gray-700 hover:bg-gray-50'
                      }
                      ${isLoading ? 'opacity-50 cursor-not-allowed' : ''}
                    `}
                  >
                    {roleInfo.icon}
                    <span>{roleInfo.title}</span>
                    {isCurrentRole && (
                      <span className="ml-auto text-xs">Atual</span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
};

export default RoleSwitcher;