import React, { useState, useEffect } from "react";
import {
  CreditCard,
  AlertCircle,
  CheckCircle,
  ExternalLink,
} from "lucide-react";

declare global {
  interface Window {
    MercadoPago: any;
  }
}

type PaymentSectionProps = {
  amount: number;
};

const PaymentSection: React.FC<PaymentSectionProps> = ({ amount }) => {
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Get API URL - PRODUCTION READY
  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }

    return "http://localhost:3001";
  };

  useEffect(() => {
    // Load MercadoPago SDK v2
    const script = document.createElement("script");
    script.src = "https://sdk.mercadopago.com/js/v2";
    script.type = "text/javascript";
    script.onload = () => {
      const publicKey = import.meta.env.VITE_MP_PUBLIC_KEY;
      console.log("MercadoPago Public Key:", publicKey ? "Found" : "Missing");

      if (publicKey && window.MercadoPago) {
        try {
          new window.MercadoPago(publicKey);
          console.log("MercadoPago SDK v2 initialized successfully");
        } catch (error) {
          console.error("Error initializing MercadoPago:", error);
        }
      } else {
        console.warn("MercadoPago public key not found or SDK not loaded");
      }
    };
    script.onerror = () => {
      console.error("Failed to load MercadoPago SDK");
    };
    document.body.appendChild(script);

    return () => {
      if (document.body.contains(script)) {
        document.body.removeChild(script);
      }
    };
  }, []);

  const handlePayment = async () => {
    try {
      setIsLoading(true);
      setError("");
      setSuccess("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      // Ensure amount is a valid number
      const numericAmount = Number(amount);
      if (isNaN(numericAmount) || numericAmount <= 0) {
        throw new Error("Valor inválido para pagamento");
      }

      console.log("Creating professional payment for amount:", numericAmount);

      const response = await fetch(
        `${apiUrl}/api/professional/create-payment`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            amount: numericAmount,
          }),
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Falha ao criar pagamento");
      }

      const data = await response.json();
      console.log("Payment preference created:", data);

      setSuccess("Redirecionando para o pagamento...");

      // Redirect to MercadoPago
      setTimeout(() => {
        window.open(data.init_point, "_blank");
      }, 1000);
    } catch (error) {
      console.error("Payment error:", error);
      setError(
        error instanceof Error
          ? error.message
          : "Ocorreu um erro ao processar o pagamento"
      );
    } finally {
      setIsLoading(false);
    }
  };

  const formatCurrency = (value: number) => {
    // Ensure value is a number before formatting
    const numericValue = Number(value);
    if (isNaN(numericValue)) {
      return "R$ 0,00";
    }

    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(numericValue);
  };

  // Ensure amount is a valid number
  const validAmount = Number(amount) || 0;

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
      <div className="flex items-center mb-4">
        <CreditCard className="h-6 w-6 text-red-600 mr-2" />
        <h2 className="text-xl font-semibold">
          Realizar Pagamento ao Convênio
        </h2>
      </div>

      <div className="space-y-4">
        <div className="bg-red-50 p-4 rounded-lg border border-red-100">
          <h3 className="font-medium mb-2 text-red-900">
            Detalhes do Pagamento
          </h3>
          <div className="space-y-2">
            <p className="text-sm text-red-700">
              Valor a ser repassado ao convênio referente às consultas
              realizadas este mês
            </p>
            <p className="font-bold text-lg text-red-900">
              Total a pagar: {formatCurrency(validAmount)}
            </p>
          </div>
        </div>

        {error && (
          <div className="bg-red-50 text-red-600 p-4 rounded-lg flex items-center border border-red-200">
            <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="bg-green-50 text-green-600 p-4 rounded-lg flex items-center border border-green-200">
            <CheckCircle className="h-5 w-5 mr-2 flex-shrink-0" />
            <span>{success}</span>
          </div>
        )}

        <button
          onClick={handlePayment}
          className={`btn btn-primary w-full flex items-center justify-center ${
            isLoading ? "opacity-70 cursor-not-allowed" : ""
          }`}
          disabled={isLoading || validAmount <= 0}
        >
          {isLoading ? (
            "Processando..."
          ) : (
            <>
              <ExternalLink className="h-5 w-5 mr-2" />
              Pagar {formatCurrency(validAmount)}
            </>
          )}
        </button>

        <div className="text-center">
          <p className="text-sm text-gray-600">
            O pagamento será processado de forma segura pelo Mercado Pago
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Você será redirecionado para completar o pagamento
          </p>
        </div>

        <div className="bg-blue-50 p-3 rounded-lg border border-blue-200">
          <p className="text-sm text-blue-700">
            <strong>💡 Dica:</strong> Após o pagamento, o valor será
            automaticamente atualizado em seu relatório financeiro.
          </p>
        </div>
      </div>
    </div>
  );
};

export default PaymentSection;
