"use client";

import type React from "react";
import { useState, useEffect } from "react";
import { useAuth } from "../../contexts/AuthContext";
import {
  CalendarClock,
  AlertCircle,
  User,
  Users,
  Clock,
  CheckCircle,
  XCircle,
  X,
  Search,
} from "lucide-react";
import DependentsSection from "./DependentsSection";
import PaymentSection from "./PaymentSection";

type Consultation = {
  id: number;
  date: string;
  value: number;
  service_name: string;
  professional_name: string;
  client_name: string;
  is_dependent: boolean;
};

type Dependent = {
  id: number;
  name: string;
  cpf: string;
  subscription_status: string;
};

const ClientHomePage: React.FC = () => {
  const { user } = useAuth();
  const [consultations, setConsultations] = useState<Consultation[]>([]);
  const [dependents, setDependents] = useState<Dependent[]>([]);
  const [filteredConsultations, setFilteredConsultations] = useState<
    Consultation[]
  >([]);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedFilter, setSelectedFilter] = useState("all");
  const [selectedPatient, setSelectedPatient] = useState("all");
  const [error, setError] = useState("");
  const [subscriptionStatus, setSubscriptionStatus] = useState<string>("");
  const [subscriptionExpiry, setSubscriptionExpiry] = useState<string | null>(
    null
  );
  const [paymentFeedback, setPaymentFeedback] = useState<{
    type: "success" | "failure" | "pending" | null;
    paymentType: string | null;
    message: string;
  }>({ type: null, paymentType: null, message: "" });
  const [searchTerm, setSearchTerm] = useState("");

  // Get API URL with fallback
  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }

    return "http://localhost:3001";
  };

  // Handle payment feedback from URL parameters
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const paymentStatus = urlParams.get("payment");
    const paymentType = urlParams.get("type");

    if (paymentStatus) {
      let message = "";

      if (paymentStatus === "success") {
        if (paymentType === "dependent") {
          message =
            "Pagamento do dependente aprovado! O dependente será ativado em breve.";
        } else if (paymentType === "agenda") {
          message =
            "Pagamento da consulta aprovado! Sua consulta foi confirmada.";
        } else {
          message = "Pagamento da assinatura aprovado com sucesso!";
        }
      } else if (paymentStatus === "failure") {
        if (paymentType === "dependent") {
          message = "Falha no pagamento do dependente. Tente novamente.";
        } else if (paymentType === "agenda") {
          message = "Falha no pagamento da consulta. Tente novamente.";
        } else {
          message = "Falha no pagamento da assinatura. Tente novamente.";
        }
      } else if (paymentStatus === "pending") {
        if (paymentType === "dependent") {
          message = "Pagamento do dependente está sendo processado.";
        } else if (paymentType === "agenda") {
          message = "Pagamento da consulta está sendo processado.";
        } else {
          message = "Pagamento da assinatura está sendo processado.";
        }
      }

      setPaymentFeedback({
        type: paymentStatus as "success" | "failure" | "pending",
        paymentType,
        message,
      });

      // Clear URL parameters after showing feedback
      const newUrl = window.location.pathname;
      window.history.replaceState({}, document.title, newUrl);

      // Auto-hide feedback after 10 seconds
      setTimeout(() => {
        setPaymentFeedback({ type: null, paymentType: null, message: "" });
      }, 10000);
    }
  }, []);

  useEffect(() => {
    const fetchData = async () => {
      try {
        setIsLoading(true);

        const token = localStorage.getItem("token");
        const apiUrl = getApiUrl();

        console.log("Fetching client data from:", apiUrl);

        // Fetch consultations
        const consultationsResponse = await fetch(
          `${apiUrl}/api/consultations/client/${user?.id}`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        if (consultationsResponse.ok) {
          const consultationsData = await consultationsResponse.json();
          console.log("Consultations loaded:", consultationsData.length);
          setConsultations(consultationsData);
        } else {
          console.warn(
            "Consultations not available:",
            consultationsResponse.status
          );
          setConsultations([]);
        }

        // Fetch dependents
        const dependentsResponse = await fetch(
          `${apiUrl}/api/dependents?client_id=${user?.id}`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );

        if (dependentsResponse.ok) {
          const dependentsData = await dependentsResponse.json();
          console.log("Dependents loaded:", dependentsData.length);
          setDependents(dependentsData);
        } else {
          console.warn("Dependents not available:", dependentsResponse.status);
          setDependents([]);
        }

        // Fetch subscription status
        const userResponse = await fetch(`${apiUrl}/api/users/${user?.id}`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });

        if (userResponse.ok) {
          const userData = await userResponse.json();
          console.log("🔍 User subscription data from API:", userData);
          console.log("🔍 Subscription status:", userData.subscription_status);
          console.log("🔍 Subscription expiry:", userData.subscription_expiry);
          setSubscriptionStatus(userData.subscription_status || "pending");
          setSubscriptionExpiry(userData.subscription_expiry);
        } else {
          console.error("❌ User data not available:", userResponse.status);
          setSubscriptionStatus("pending");
        }
      } catch (error) {
        console.error("Error fetching data:", error);
        setError("Não foi possível carregar alguns dados. Tente novamente.");
      } finally {
        setIsLoading(false);
      }
    };

    if (user?.id) {
      fetchData();
    }
  }, [user?.id]);

  // Filter consultations based on selected filter
  useEffect(() => {
    let filtered = consultations;

    // Filter by selected user (all, titular, or specific dependent)
    if (selectedFilter === "titular") {
      filtered = filtered.filter((c) => c.client_name === user?.name);
    } else if (selectedFilter !== "all") {
      const dependent = dependents.find(
        (d) => d.id.toString() === selectedFilter
      );
      if (dependent) {
        filtered = filtered.filter((c) => c.client_name === dependent.name);
      }
    }

    // Filter by search term
    if (searchTerm.trim()) {
      const searchValue = searchTerm.toLowerCase().trim();
      filtered = filtered.filter(
        (consultation) =>
          consultation.client_name?.toLowerCase().includes(searchValue) ||
          consultation.service_name?.toLowerCase().includes(searchValue) ||
          consultation.professional_name?.toLowerCase().includes(searchValue)
      );
    }

    setFilteredConsultations(filtered);
  }, [consultations, selectedFilter, dependents, user?.name, searchTerm]);

  const formatDate = (dateString: string) => {
    const clientHomeUtcDate = new Date(dateString);
    const clientHomeLocalDate = new Date(
      clientHomeUtcDate.getTime() - 3 * 60 * 60 * 1000
    );
    return clientHomeLocalDate.toLocaleDateString("pt-BR", {
      day: "2-digit",
      month: "long",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const formatCurrency = (value: number) => {
    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(value);
  };

  const getFilterOptions = () => {
    const options = [
      {
        value: "all",
        label: "Todas as consultas",
        icon: <CalendarClock className="h-4 w-4" />,
      },
      {
        value: "titular",
        label: `${user?.name} (Titular)`,
        icon: <User className="h-4 w-4" />,
      },
    ];

    // Only show active dependents in filter (check individual status)
    dependents
      .filter((d) => d.subscription_status === "active")
      .forEach((dependent) => {
        options.push({
          value: dependent.id.toString(),
          label: dependent.name,
          icon: <Users className="h-4 w-4" />,
        });
      });

    return options;
  };

  const dismissPaymentFeedback = () => {
    setPaymentFeedback({ type: null, paymentType: null, message: "" });
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Olá, {user?.name}</h1>
        <p className="text-gray-600">Bem-vindo ao seu painel de cliente.</p>
      </div>

      {/* Payment Feedback */}
      {paymentFeedback.type && (
        <div
          className={`border-l-4 p-4 mb-6 relative ${
            paymentFeedback.type === "success"
              ? "bg-green-50 border-green-600"
              : paymentFeedback.type === "failure"
              ? "bg-red-50 border-red-600"
              : "bg-yellow-50 border-yellow-600"
          }`}
        >
          <div className="flex items-start">
            <div className="flex-shrink-0">
              {paymentFeedback.type === "success" && (
                <CheckCircle className="h-5 w-5 text-green-600" />
              )}
              {paymentFeedback.type === "failure" && (
                <XCircle className="h-5 w-5 text-red-600" />
              )}
              {paymentFeedback.type === "pending" && (
                <Clock className="h-5 w-5 text-yellow-600" />
              )}
            </div>
            <div className="ml-3 flex-1">
              <p
                className={`font-medium ${
                  paymentFeedback.type === "success"
                    ? "text-green-800"
                    : paymentFeedback.type === "failure"
                    ? "text-red-800"
                    : "text-yellow-800"
                }`}
              >
                {paymentFeedback.message}
              </p>
            </div>
            <button
              onClick={dismissPaymentFeedback}
              className={`ml-3 ${
                paymentFeedback.type === "success"
                  ? "text-green-600 hover:text-green-800"
                  : paymentFeedback.type === "failure"
                  ? "text-red-600 hover:text-red-800"
                  : "text-yellow-600 hover:text-yellow-800"
              }`}
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>
      )}

      {subscriptionStatus === "expired" && (
        <div className="bg-red-50 border-l-4 border-red-600 p-4 mb-6">
          <div className="flex items-center">
            <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
            <p className="text-red-700">
              Sua assinatura está vencida. Por favor, renove para continuar
              utilizando os serviços.
            </p>
          </div>
        </div>
      )}

      {/* Subscription Status Display for Active Clients */}
      {subscriptionStatus === "active" && subscriptionExpiry && (
        <div className="bg-green-50 border-l-4 border-green-600 p-4 mb-6">
          <div className="flex items-center">
            <CheckCircle className="h-5 w-5 text-green-600 mr-2" />
            <div>
              <p className="text-green-700 font-medium">
                Sua assinatura está ativa
              </p>
              <p className="text-green-600 text-sm">
                Válida até:{" "}
                {new Date(subscriptionExpiry).toLocaleDateString("pt-BR", {
                  day: "2-digit",
                  month: "long",
                  year: "numeric",
                })}
              </p>
            </div>
          </div>
        </div>
      )}

      {subscriptionStatus !== "active" && (
        <>
          {subscriptionStatus === "pending" && (
            <div className="bg-yellow-50 border-l-4 border-yellow-600 p-4 mb-6">
              <div className="flex items-center">
                <AlertCircle className="h-5 w-5 text-yellow-600 mr-2" />
                <p className="text-yellow-700">
                  Complete seu cadastro realizando o pagamento da assinatura.
                </p>
              </div>
            </div>
          )}

          {user && (
            <PaymentSection
              userId={user.id}
              subscriptionStatus={subscriptionStatus}
              subscriptionExpiry={subscriptionExpiry}
            />
          )}
        </>
      )}

      {user && <DependentsSection clientId={user.id} />}

      <div className="card mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <CalendarClock className="h-6 w-6 text-red-600 mr-2" />
            <h2 className="text-xl font-semibold">Histórico de Consultas</h2>
          </div>

          {/* Filters */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            {/* Search input */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Buscar por cliente ou serviço..."
                className="w-full pl-12 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
              />
            </div>

            {/* Filter dropdown */}
            {(consultations.length > 0 || dependents.length > 0) && (
              <select
                value={selectedFilter}
                onChange={(e) => setSelectedFilter(e.target.value)}
                className="input"
              >
                {getFilterOptions().map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            )}
          </div>
        </div>

        {isLoading ? (
          <div className="text-center py-8">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando consultas...</p>
          </div>
        ) : error ? (
          <div className="bg-red-50 text-red-600 p-4 rounded-md">{error}</div>
        ) : filteredConsultations.length === 0 ? (
          <div className="text-center py-8 bg-gray-50 rounded-lg">
            <CalendarClock className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {selectedFilter === "all"
                ? "Nenhuma consulta encontrada"
                : `Nenhuma consulta encontrada para ${
                    selectedFilter === "titular"
                      ? "o titular"
                      : dependents.find(
                          (d) => d.id.toString() === selectedFilter
                        )?.name || "este usuário"
                  }`}
            </h3>
            <p className="text-gray-600">
              {selectedFilter === "all"
                ? "Você ainda não possui consultas registradas."
                : "Não há consultas registradas para este usuário."}
            </p>
          </div>
        ) : (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Data</th>
                  <th>Paciente</th>
                  <th>Serviço</th>
                  <th>Profissional</th>
                </tr>
              </thead>
              <tbody>
                {filteredConsultations.map((consultation) => (
                  <tr key={consultation.id}>
                    <td>{formatDate(consultation.date)}</td>
                    <td>
                      <div className="flex items-center">
                        {consultation.client_name === user?.name ? (
                          <User className="h-4 w-4 text-green-600 mr-2" />
                        ) : (
                          <Users className="h-4 w-4 text-blue-600 mr-2" />
                        )}
                        {consultation.client_name}
                        {consultation.client_name === user?.name && (
                          <span className="ml-2 px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs">
                            Titular
                          </span>
                        )}
                      </div>
                    </td>
                    <td>{consultation.service_name}</td>
                    <td>{consultation.professional_name}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Summary */}
        {filteredConsultations.length > 0 && (
          <div className="mt-4 p-4 bg-gray-50 rounded-lg">
            <div className="text-center">
              <span className="text-sm text-gray-600">
                {filteredConsultations.length} consulta(s) encontrada(s)
                {selectedFilter !== "all" && (
                  <span className="ml-1">
                    para{" "}
                    {selectedFilter === "titular"
                      ? "o titular"
                      : dependents.find(
                          (d) => d.id.toString() === selectedFilter
                        )?.name}
                  </span>
                )}
              </span>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h2 className="text-xl font-semibold mb-4">Informações do Convênio</h2>
        <p className="text-gray-600">
          Informações sobre seu convênio e benefícios disponíveis.
        </p>
      </div>
    </div>
  );
};

export default ClientHomePage;
