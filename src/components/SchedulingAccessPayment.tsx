import React, { useState } from "react";
import {
  Calendar,
  CreditCard,
  Gift,
  Clock,
  CheckCircle,
  AlertCircle,
  ExternalLink,
  Star,
} from "lucide-react";

declare global {
  interface Window {
    MercadoPago: any;
  }
}

type SchedulingAccessPaymentProps = {
  professionalName: string;
  onPaymentSuccess?: () => void;
};

const SchedulingAccessPayment: React.FC<SchedulingAccessPaymentProps> = ({
  professionalName,
  onPaymentSuccess,
}) => {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Get API URL
  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }
    return "http://localhost:3001";
  };

  const handlePayment = async () => {
    try {
      setIsLoading(true);
      setError("");
      setSuccess("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      console.log("🔄 Creating agenda payment...");

      const response = await fetch(
        `${apiUrl}/api/professional/create-agenda-payment`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            duration_days: 30, // 1 month
          }),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao criar pagamento");
      }

      const data = await response.json();
      console.log("✅ Payment preference created:", data);

      setSuccess("Redirecionando para o pagamento...");

      // Clear any existing payment feedback
      const currentUrl = new URL(window.location.href);
      currentUrl.searchParams.delete("payment");
      currentUrl.searchParams.delete("type");
      window.history.replaceState({}, document.title, currentUrl.toString());

      // Redirect to MercadoPago
      setTimeout(() => {
        window.location.href = data.init_point;
      }, 1000);
    } catch (error) {
      console.error("❌ Payment error:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao processar pagamento"
      );
    } finally {
      setIsLoading(false);
    }
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(value);
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center p-4">
      <div className="max-w-2xl w-full">
        <div className="bg-white rounded-xl shadow-lg p-8">
          {/* Header */}
          <div className="text-center mb-8">
            <div className="w-20 h-20 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Calendar className="h-10 w-10 text-red-600" />
            </div>
            <h1 className="text-3xl font-bold text-gray-900 mb-2">
              Acesso à Agenda
            </h1>
            <p className="text-gray-600">
              Olá, <span className="font-medium">{professionalName}</span>! Para
              usar o sistema de agendamentos, você precisa de uma assinatura
              ativa.
            </p>
          </div>

          {/* Features Section */}
          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-xl p-6 mb-8">
            <h2 className="text-xl font-bold text-gray-900 mb-4 flex items-center">
              <Star className="h-6 w-6 text-yellow-500 mr-2" />O que está
              incluído na assinatura:
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 mr-3 flex-shrink-0" />
                  <span className="text-gray-700">
                    Sistema completo de agendamentos
                  </span>
                </div>
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 mr-3 flex-shrink-0" />
                  <span className="text-gray-700">
                    Gestão de pacientes particulares
                  </span>
                </div>
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 mr-3 flex-shrink-0" />
                  <span className="text-gray-700">
                    Prontuários médicos digitais
                  </span>
                </div>
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 mr-3 flex-shrink-0" />
                  <span className="text-gray-700">
                    Geração de documentos médicos
                  </span>
                </div>
              </div>

              <div className="space-y-3">
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 mr-3 flex-shrink-0" />
                  <span className="text-gray-700">Relatórios detalhados</span>
                </div>
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 mr-3 flex-shrink-0" />
                  <span className="text-gray-700">
                    Notificações via WhatsApp
                  </span>
                </div>
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 mr-3 flex-shrink-0" />
                  <span className="text-gray-700">
                    Suporte técnico especializado
                  </span>
                </div>
                <div className="flex items-center">
                  <CheckCircle className="h-5 w-5 text-green-600 mr-3 flex-shrink-0" />
                  <span className="text-gray-700">
                    Atualizações automáticas
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Pricing Section */}
          <div className="bg-red-50 border border-red-200 rounded-xl p-6 mb-8">
            <div className="text-center">
              <h3 className="text-2xl font-bold text-red-900 mb-2">
                Assinatura Mensal
              </h3>
              <div className="flex items-center justify-center mb-4">
                <span className="text-4xl font-bold text-red-600">
                  {formatCurrency(24.99)}
                </span>
                <span className="text-gray-600 ml-2">/mês</span>
              </div>
              <p className="text-red-700 text-sm">
                Acesso completo ao sistema de agendamentos e todas as
                funcionalidades
              </p>
            </div>
          </div>

          {/* Payment Feedback */}
          {error && (
            <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6 flex items-center">
              <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0" />
              {error}
            </div>
          )}

          {success && (
            <div className="bg-green-50 text-green-600 p-4 rounded-lg mb-6 flex items-center">
              <CheckCircle className="h-5 w-5 mr-2 flex-shrink-0" />
              {success}
            </div>
          )}

          {/* Payment Button */}
          <div className="space-y-4">
            <button
              onClick={handlePayment}
              className={`w-full btn btn-primary flex items-center justify-center text-lg py-4 ${
                isLoading ? "opacity-70 cursor-not-allowed" : ""
              }`}
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-white mr-3"></div>
                  Processando...
                </>
              ) : (
                <>
                  <CreditCard className="h-6 w-6 mr-3" />
                  Assinar por {formatCurrency(24.99)}/mês
                </>
              )}
            </button>

            <div className="text-center">
              <p className="text-sm text-gray-600">
                Pagamento seguro processado pelo Mercado Pago
              </p>
              <p className="text-xs text-gray-500 mt-1">
                Você será redirecionado para completar o pagamento
              </p>
            </div>
          </div>

          {/* Benefits Section */}
          <div className="mt-8 pt-8 border-t border-gray-200">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 text-center">
              Por que assinar a agenda?
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="text-center">
                <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-3">
                  <Clock className="h-6 w-6 text-blue-600" />
                </div>
                <h4 className="font-medium text-gray-900 mb-2">Organização</h4>
                <p className="text-sm text-gray-600">
                  Gerencie seus horários de forma profissional e eficiente
                </p>
              </div>

              <div className="text-center">
                <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-3">
                  <Gift className="h-6 w-6 text-green-600" />
                </div>
                <h4 className="font-medium text-gray-900 mb-2">
                  Produtividade
                </h4>
                <p className="text-sm text-gray-600">
                  Aumente sua produtividade com ferramentas especializadas
                </p>
              </div>

              <div className="text-center">
                <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-3">
                  <Star className="h-6 w-6 text-purple-600" />
                </div>
                <h4 className="font-medium text-gray-900 mb-2">
                  Profissionalismo
                </h4>
                <p className="text-sm text-gray-600">
                  Ofereça um atendimento mais profissional aos seus pacientes
                </p>
              </div>
            </div>
          </div>

          {/* Contact Info */}
          <div className="mt-8 pt-6 border-t border-gray-200 text-center">
            <p className="text-sm text-gray-600">
              Dúvidas? Entre em contato:{" "}
              <span className="font-medium">(64) 98124-9199</span>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SchedulingAccessPayment;
