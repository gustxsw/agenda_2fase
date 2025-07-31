import React, { useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import { Link, useNavigate } from "react-router-dom";
import { Users, Award, Calendar, Activity, UserPlus } from "lucide-react";

const LoginPage: React.FC = () => {
  const [cpf, setCpf] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  const { login, selectRole } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!/^\d{11}$/.test(cpf)) {
      setError("CPF deve conter 11 dígitos numéricos");
      return;
    }

    if (!password) {
      setError("Senha é obrigatória");
      return;
    }

    try {
      setIsLoading(true);
      console.log("🔄 Iniciando processo de login...");
      
      const result = await login(cpf, password);
      console.log("✅ Login result:", result);

      if (result.needsRoleSelection) {
        console.log("🎯 Usuário tem múltiplas roles - NOVA ABORDAGEM");
        
        // SALVAR NO LOCALSTORAGE TEMPORARIAMENTE
        localStorage.setItem('tempUser', JSON.stringify(result.user));
        
        // REDIRECIONAR PARA PÁGINA DE SELEÇÃO
        navigate('/select-role', { replace: true });
        
      } else {
        console.log("🎯 Usuário tem role única, selecionando automaticamente");
        await selectRole(result.user.id, result.user.roles[0]);
      }
    } catch (error) {
      console.error("❌ Erro no login:", error);
      if (error instanceof Error) {
        setError(error.message);
      } else {
        setError("Ocorreu um erro ao fazer login");
      }
    } finally {
      setIsLoading(false);
    }
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 11);
    setCpf(limitedValue);
  };

  const formattedCpf = cpf
    ? cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4")
    : "";

  return (
    <div className="min-h-screen flex flex-col bg-gray-50">
      <div className="flex flex-1">
        {/* Left side with text */}
        <div className="hidden lg:flex lg:w-[60%] relative">
          <div className="absolute inset-0 bg-gradient-to-r from-gray-900/90 to-gray-900/60 z-10" />
          <img
            src="/familiafeliz.jpg"
            alt="Família feliz"
            className="absolute inset-0 w-full h-full object-cover"
          />
          <div className="relative z-20 p-16 text-white w-full flex items-center">
            <div className="max-w-xl">
              <div className="mb-16">
                <div className="flex items-center mb-8">
                  <Activity className="h-10 w-10 mr-4" strokeWidth={1.5} />
                  <h1 className="text-5xl font-light tracking-tight">
                    Convênio Quiro Ferreira
                  </h1>
                </div>
                <h2 className="text-2xl font-light leading-relaxed text-gray-200">
                  Sistema completo para gestão de consultas e serviços
                </h2>
              </div>

              <div className="space-y-8 mb-16">
                <div className="flex items-start group">
                  <Users
                    className="h-6 w-6 mr-4 mt-1 transition-transform group-hover:scale-110"
                    strokeWidth={1.5}
                  />
                  <p className="text-lg text-gray-200 leading-relaxed">
                    Rede multidisciplinar de especialistas: saúde, bem-estar,
                    educação e muito mais.
                  </p>
                </div>
                <div className="flex items-start group">
                  <Award
                    className="h-6 w-6 mr-4 mt-1 transition-transform group-hover:scale-110"
                    strokeWidth={1.5}
                  />
                  <p className="text-lg text-gray-200 leading-relaxed">
                    Profissionais qualificados: atendimento de excelência em
                    diversas áreas.
                  </p>
                </div>
                <div className="flex items-start group">
                  <Calendar
                    className="h-6 w-6 mr-4 mt-1 transition-transform group-hover:scale-110"
                    strokeWidth={1.5}
                  />
                  <p className="text-lg text-gray-200 leading-relaxed">
                    Comodidade para você: agende, consulte e gerencie com
                    facilidade.
                  </p>
                </div>
              </div>

              <div className="bg-white/10 backdrop-blur-sm rounded-xl p-8 border border-white/10">
                <h3 className="text-xl font-medium mb-3">Área do Cliente</h3>
                <p className="text-gray-200 leading-relaxed">
                  Consulte seu histórico, gerencie dependentes e acompanhe seus
                  atendimentos.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Right side with login form */}
        <div className="w-full lg:w-[40%] flex items-center justify-center p-8 bg-white">
          <div className="w-full max-w-md">
            <div className="text-center mb-12">
              <img
                src="/logo_quiroferreira.svg"
                alt="Logo Quiro Ferreira"
                className="w-48 mx-auto mb-8"
              />
            </div>

            <div className="mb-8">
              <h2 className="text-2xl font-light text-gray-900 mb-2">
                Acesse sua conta
              </h2>
              <p className="text-gray-600">
                Digite suas credenciais para continuar
              </p>
            </div>

            {error && (
              <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              <div>
                <label
                  htmlFor="cpf"
                  className="block text-sm font-medium text-gray-700 mb-1"
                >
                  CPF
                </label>
                <input
                  id="cpf"
                  type="text"
                  value={formattedCpf}
                  onChange={(e) => formatCpf(e.target.value)}
                  className="w-full px-4 py-3 rounded-lg border border-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-200 transition-all"
                  placeholder="Digite seu CPF"
                  disabled={isLoading}
                  required
                />
              </div>

              <div>
                <label
                  htmlFor="password"
                  className="block text-sm font-medium text-gray-700 mb-1"
                >
                  Senha
                </label>
                <input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full px-4 py-3 rounded-lg border border-gray-200 focus:outline-none focus:ring-2 focus:ring-gray-200 transition-all"
                  placeholder="Digite sua senha"
                  disabled={isLoading}
                  required
                />
              </div>

              <button
                type="submit"
                className={`w-full py-3 bg-red-700 text-white rounded-lg hover:bg-red-800 transition-colors ${
                  isLoading ? "opacity-70 cursor-not-allowed" : ""
                }`}
                disabled={isLoading}
              >
                {isLoading ? "Aguarde..." : "Entrar"}
              </button>
            </form>

            {/* Registration link */}
            <div className="mt-6 text-center">
              <p className="text-sm text-gray-600 mb-4">
                Não possui uma conta?
              </p>
              <Link
                to="/register"
                className="inline-flex items-center justify-center w-full py-3 px-4 border border-red-600 text-red-600 rounded-lg hover:bg-red-50 transition-colors font-medium"
              >
                <UserPlus className="h-5 w-5 mr-2" />
                Criar conta de cliente
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LoginPage;