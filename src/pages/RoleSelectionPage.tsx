import React, { useState, useEffect } from "react";
import { useAuth } from "../contexts/AuthContext";
import { useNavigate, Link } from "react-router-dom";
import { Users, Award, Briefcase, ArrowLeft, RefreshCw } from "lucide-react";

const RoleSelectionPage: React.FC = () => {
  const [user, setUser] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  
  const { selectRole } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    // RECUPERAR USUÁRIO DO LOCALSTORAGE
    const tempUser = localStorage.getItem('tempUser');
    if (tempUser) {
      try {
        const userData = JSON.parse(tempUser);
        console.log('🎯 Usuário recuperado do localStorage:', userData);
        setUser(userData);
      } catch (error) {
        console.error('❌ Erro ao recuperar usuário:', error);
        navigate('/', { replace: true }); // 🔥 VAI PARA A RAIZ (LOGIN)
      }
    } else {
      console.log('❌ Nenhum usuário temporário encontrado');
      navigate('/', { replace: true }); // 🔥 VAI PARA A RAIZ (LOGIN)
    }
  }, [navigate]);

  const handleRoleSelect = async (role: string) => {
    if (!user) return;

    try {
      setIsLoading(true);
      setError("");
      console.log("🎯 Selecionando role:", role, "para usuário:", user.id);
      
      await selectRole(user.id, role);
      
      // LIMPAR DADOS TEMPORÁRIOS
      localStorage.removeItem('tempUser');
      
    } catch (error) {
      console.error("❌ Erro ao selecionar role:", error);
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError("Ocorreu um erro ao selecionar a role");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleBackToLogin = () => {
    localStorage.removeItem('tempUser');
    navigate('/', { replace: true }); // 🔥 VAI PARA A RAIZ (LOGIN)
  };

  const getRoleInfo = (role: string) => {
    switch (role) {
      case 'client':
        return {
          title: 'Cliente',
          description: 'Acesse seus dados, consulte profissionais e gerencie dependentes',
          icon: <Users className="h-8 w-8" />,
          color: 'bg-green-500 hover:bg-green-600',
          bgColor: 'bg-green-50',
          textColor: 'text-green-700'
        };
      case 'professional':
        return {
          title: 'Profissional',
          description: 'Registre consultas, visualize relatórios e gerencie pagamentos',
          icon: <Briefcase className="h-8 w-8" />,
          color: 'bg-blue-500 hover:bg-blue-600',
          bgColor: 'bg-blue-50',
          textColor: 'text-blue-700'
        };
      case 'admin':
        return {
          title: 'Administrador',
          description: 'Gerencie usuários, serviços e visualize relatórios completos',
          icon: <Award className="h-8 w-8" />,
          color: 'bg-red-500 hover:bg-red-600',
          bgColor: 'bg-red-50',
          textColor: 'text-red-700'
        };
      default:
        return {
          title: role,
          description: 'Acesso ao sistema',
          icon: <Users className="h-8 w-8" />,
          color: 'bg-gray-500 hover:bg-gray-600',
          bgColor: 'bg-gray-50',
          textColor: 'text-gray-700'
        };
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Carregando...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="max-w-2xl w-full">
        <div className="text-center mb-8">
          <img
            src="/logo_quiroferreira.svg"
            alt="Logo Quiro Ferreira"
            className="w-32 mx-auto mb-6"
          />
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            Bem-vindo, {user.name}!
          </h1>
          <p className="text-gray-600">
            Você possui múltiplos acessos. Selecione como deseja entrar no sistema:
          </p>
        </div>

        <div className="mb-6">
          <button
            onClick={handleBackToLogin}
            className="inline-flex items-center text-red-600 hover:text-red-700 transition-colors"
            disabled={isLoading}
          >
            <ArrowLeft className="h-4 w-4 mr-2" />
            Voltar para o login
          </button>
        </div>

        {error && (
          <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6 text-center">
            {error}
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {user.roles.map((role: string) => {
            const roleInfo = getRoleInfo(role);
            return (
              <button
                key={role}
                onClick={() => handleRoleSelect(role)}
                disabled={isLoading}
                className={`
                  p-6 rounded-xl border-2 border-transparent transition-all duration-200
                  ${roleInfo.bgColor} hover:border-gray-200 hover:shadow-lg
                  ${isLoading ? 'opacity-50 cursor-not-allowed' : 'hover:scale-105'}
                  focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-gray-500
                `}
              >
                <div className="text-center">
                  <div className={`inline-flex items-center justify-center w-16 h-16 rounded-full ${roleInfo.color} text-white mb-4`}>
                    {roleInfo.icon}
                  </div>
                  <h3 className={`text-xl font-semibold mb-2 ${roleInfo.textColor}`}>
                    {roleInfo.title}
                  </h3>
                  <p className="text-gray-600 text-sm leading-relaxed">
                    {roleInfo.description}
                  </p>
                </div>
              </button>
            );
          })}
        </div>

        {isLoading && (
          <div className="text-center mt-8">
            <div className="inline-flex items-center">
              <RefreshCw className="h-6 w-6 animate-spin text-red-600 mr-3" />
              <span className="text-gray-600">Processando seleção...</span>
            </div>
          </div>
        )}

        <div className="text-center mt-8">
          <p className="text-sm text-gray-500">
            Você pode alternar entre os diferentes acessos a qualquer momento através do menu superior.
          </p>
        </div>
      </div>
    </div>
  );
};

export default RoleSelectionPage;