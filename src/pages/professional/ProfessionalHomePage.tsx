import type React from "react";
import { useState, useEffect } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { Link } from "react-router-dom";
import {
  CalendarClock,
  PlusCircle,
  DollarSign,
  TrendingUp,
  Users,
  AlertCircle,
  RefreshCw,
  Camera,
  Upload,
  CheckCircle,
  Clock,
  Search,
} from "lucide-react";
import PaymentSection from "./PaymentSection";
import { formatToBrazilDateTime } from "../../utils/dateHelpers";

// Consultations Table Component with Search
type ConsultationsTableProps = {
  consultations: {
    date: string;
    client_name: string;
    service_name: string;
    total_value: number;
    amount_to_pay: number;
  }[];
  formatDate: (date: string) => string;
  formatCurrency: (value: number | string) => string;
};

const ConsultationsTable: React.FC<ConsultationsTableProps> = ({
  consultations,
  formatDate,
  formatCurrency,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [filteredConsultations, setFilteredConsultations] =
    useState(consultations);

  useEffect(() => {
    if (searchTerm.trim()) {
      const filtered = consultations.filter(
        (consultation) =>
          consultation.client_name
            ?.toLowerCase()
            .includes(searchTerm.toLowerCase()) ||
          consultation.service_name
            ?.toLowerCase()
            .includes(searchTerm.toLowerCase())
      );
      setFilteredConsultations(filtered);
    } else {
      setFilteredConsultations(consultations);
    }
  }, [searchTerm, consultations]);

  return (
    <div>
      {/* Search Bar */}
      <div className="mb-4">
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
        {searchTerm && (
          <p className="text-sm text-gray-600 mt-2">
            {filteredConsultations.length} de {consultations.length} consulta(s)
            encontrada(s)
          </p>
        )}
      </div>

      {/* Table Container with Fixed Height */}
      <div className="border border-gray-200 rounded-lg overflow-hidden">
        <div className="max-h-96 overflow-y-auto">
          <table className="min-w-full">
            <thead className="bg-gray-50 sticky top-0">
              <tr>
                <th className="text-left py-3 px-4 font-medium text-gray-700 border-b border-gray-200">
                  Data
                </th>
                <th className="text-left py-3 px-4 font-medium text-gray-700 border-b border-gray-200">
                  Cliente
                </th>
                <th className="text-left py-3 px-4 font-medium text-gray-700 border-b border-gray-200">
                  Serviço
                </th>
                <th className="text-right py-3 px-4 font-medium text-gray-700 border-b border-gray-200">
                  Valor Total
                </th>
                <th className="text-right py-3 px-4 font-medium text-gray-700 border-b border-gray-200">
                  Valor a Pagar
                </th>
              </tr>
            </thead>
            <tbody>
              {filteredConsultations.map((consultation, index) => (
                <tr
                  key={index}
                  className="border-b border-gray-100 hover:bg-gray-50"
                >
                  <td className="py-3 px-4 text-sm text-gray-600">
                    {formatDate(consultation.date)}
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-900">
                    {consultation.client_name || "N/A"}
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-600">
                    {consultation.service_name || "N/A"}
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-900 text-right font-medium">
                    {formatCurrency(consultation.total_value)}
                  </td>
                  <td className="py-3 px-4 text-sm text-red-600 text-right font-medium">
                    {formatCurrency(consultation.amount_to_pay)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Table Footer with Summary */}
        <div className="bg-gray-50 px-4 py-3 border-t border-gray-200">
          <div className="flex justify-between items-center text-sm">
            <span className="text-gray-600">
              {filteredConsultations.length} consulta(s){" "}
              {searchTerm && "filtrada(s)"}
            </span>
            <div className="flex space-x-6">
              <span className="text-gray-900 font-medium">
                Total:{" "}
                {formatCurrency(
                  filteredConsultations.reduce(
                    (sum, c) =>
                      sum + Number.parseFloat(String(c.total_value || 0)),
                    0
                  )
                )}
              </span>
              <span className="text-red-600 font-medium">
                A Pagar:{" "}
                {formatCurrency(
                  filteredConsultations.reduce(
                    (sum, c) =>
                      sum + Number.parseFloat(String(c.amount_to_pay || 0)),
                    0
                  )
                )}
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

type RevenueReport = {
  summary: {
    professional_percentage: number;
    total_revenue: number;
    consultation_count: number;
    amount_to_pay: number;
  };
  consultations: {
    date: string;
    client_name: string;
    service_name: string;
    total_value: number;
    amount_to_pay: number;
  }[];
};

const ProfessionalHomePage: React.FC = () => {
  const { user } = useAuth();
  const [revenueReport, setRevenueReport] = useState<RevenueReport | null>(
    null
  );
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [photoUrl, setPhotoUrl] = useState<string | null>(null);
  const [isUploadingPhoto, setIsUploadingPhoto] = useState(false);
  const [uploadError, setUploadError] = useState("");
  const [uploadSuccess, setUploadSuccess] = useState("");

  // Get API URL with fallback
  const getApiUrl = () => {
    if (
      window.location.hostname === "testes-quiro-ferreira.onrender.com" ||
      window.location.hostname === "testes-quiro-ferreira.onrender.com"
    ) {
      return "https://testes-quiro-ferreira.onrender.com";
    }

    return "http://localhost:3001";
  };

  const getDefaultDateRange = () => {
    const now = new Date();
    const firstDay = new Date(now.getFullYear(), now.getMonth(), 1);
    const lastDay = new Date(now.getFullYear(), now.getMonth() + 1, 0);
    return {
      start: firstDay.toISOString().split("T")[0],
      end: lastDay.toISOString().split("T")[0],
    };
  };

  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();
      const dateRange = getDefaultDateRange();

      console.log("🔄 Fetching professional data from:", apiUrl);
      console.log("🔄 Date range:", dateRange);
      console.log("🔄 User ID:", user?.id);

      // Fetch user data to get photo_url
      const userResponse = await fetch(`${apiUrl}/api/users/${user?.id}`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      if (userResponse.ok) {
        const userData = await userResponse.json();
        console.log("User data loaded:", userData);
        setPhotoUrl(userData.photo_url);
      } else {
        console.warn("User data not available:", userResponse.status);
      }

      // 🔥 LIBERADO: Sempre buscar dados de receita
      const revenueResponse = await fetch(
        `${apiUrl}/api/reports/professional-revenue?start_date=${dateRange.start}&end_date=${dateRange.end}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      console.log("📡 Revenue response status:", revenueResponse.status);

      if (!revenueResponse.ok) {
        const errorData = await revenueResponse.json();
        console.error("❌ Revenue response error:", errorData);
        // Don't throw error, just log it and continue
        console.warn("Revenue data not available, continuing without it");
        setRevenueReport(null);
        return;
      }

      const revenueData = await revenueResponse.json();
      console.log("✅ Revenue data received:", revenueData);

      // 🔎 Log temporário para ver formato das datas
      const sample = revenueData?.consultations
        ?.slice?.(0, 3)
        ?.map((c: any) => c?.date);
      console.log("⏱️ RAW dates sample:", sample);

      setRevenueReport(revenueData);
    } catch (error) {
      console.error("❌ Error fetching data:", error);
      setError(
        error instanceof Error
          ? error.message
          : "Não foi possível carregar os dados. Verifique sua conexão e tente novamente."
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handlePhotoUpload = async (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith("image/")) {
      setUploadError("Por favor, selecione apenas arquivos de imagem");
      return;
    }

    // Validate file size (5MB)
    if (file.size > 5 * 1024 * 1024) {
      setUploadError("A imagem deve ter no máximo 5MB");
      return;
    }

    try {
      setIsUploadingPhoto(true);
      setUploadError("");
      setUploadSuccess("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const formData = new FormData();
      formData.append("image", file);

      const response = await fetch(`${apiUrl}/api/upload-image`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Falha ao fazer upload da imagem");
      }

      const data = await response.json();
      setPhotoUrl(data.imageUrl);
      setUploadSuccess("Imagem atualizada com sucesso!");

      // Clear success message after 3 seconds
      setTimeout(() => {
        setUploadSuccess("");
      }, 3000);
    } catch (error) {
      console.error("Error uploading photo:", error);
      setUploadError(
        error instanceof Error
          ? error.message
          : "Erro ao fazer upload da imagem"
      );
    } finally {
      setIsUploadingPhoto(false);
    }
  };

  useEffect(() => {
    if (user?.id) {
      fetchData();
    }
  }, [user?.id]);

  // ⚠️ Gambiarra provisória — ajusta -3h no frontend apenas para exibição
  const formatDate = (dateString: string) => {
    if (!dateString) return "";

    // Converte a string em data
    const d = new Date(dateString);

    // Subtrai 3 horas
    d.setHours(d.getHours() - 3);

    // Formata normalmente
    return d.toLocaleString("pt-BR", {
      dateStyle: "short",
      timeStyle: "short",
    });
  };

  const formatCurrency = (value: number | string) => {
    const numericValue =
      typeof value === "string" ? Number.parseFloat(value) : value;
    if (isNaN(numericValue)) return "R$ 0,00";

    return new Intl.NumberFormat("pt-BR", {
      style: "currency",
      currency: "BRL",
    }).format(numericValue);
  };

  const handleRetry = () => {
    fetchData();
  };

  return (
    <div>
      <div className="flex justify-between items-start mb-6">
        <div className="flex items-center space-x-4">
          {/* Professional Photo */}
          <div className="relative">
            <div className="w-16 h-16 rounded-full overflow-hidden border-2 border-red-100">
              {photoUrl ? (
                <img
                  src={photoUrl || "/placeholder.svg"}
                  alt={`Foto de ${user?.name}`}
                  className="w-full h-full object-cover"
                  onError={(e) => {
                    const target = e.target as HTMLImageElement;
                    target.style.display = "none";
                    target.nextElementSibling?.classList.remove("hidden");
                  }}
                />
              ) : null}
              <div
                className={`w-full h-full bg-red-100 flex items-center justify-center ${
                  photoUrl ? "hidden" : ""
                }`}
              >
                <Camera className="h-6 w-6 text-red-600" />
              </div>
            </div>

            {/* Upload button */}
            <label className="absolute -bottom-1 -right-1 bg-red-600 text-white rounded-full p-1.5 cursor-pointer hover:bg-red-700 transition-colors shadow-sm">
              <Upload className="h-3 w-3" />
              <input
                type="file"
                accept="image/*"
                onChange={handlePhotoUpload}
                className="hidden"
                disabled={isUploadingPhoto}
              />
            </label>

            {isUploadingPhoto && (
              <div className="absolute inset-0 bg-black bg-opacity-50 rounded-full flex items-center justify-center">
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              </div>
            )}
          </div>

          <div>
            <h1 className="text-2xl font-bold text-gray-900">
              Olá, {user?.name}
            </h1>
            <p className="text-gray-600">
              Bem-vindo ao seu painel de profissional.
            </p>
          </div>
        </div>

        <div className="flex space-x-3">
          {error && (
            <button
              onClick={handleRetry}
              className="btn btn-outline flex items-center"
              disabled={isLoading}
            >
              <RefreshCw
                className={`h-5 w-5 mr-2 ${isLoading ? "animate-spin" : ""}`}
              />
              Tentar Novamente
            </button>
          )}

          <Link
            to="/professional/register-consultation"
            className="btn btn-primary flex items-center"
          >
            <PlusCircle className="h-5 w-5 mr-2" />
            Nova Consulta
          </Link>
        </div>
      </div>

      {/* Upload feedback messages */}
      {uploadError && (
        <div className="bg-red-50 border-l-4 border-red-600 p-4 mb-6">
          <div className="flex items-center">
            <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
            <p className="text-red-700">{uploadError}</p>
          </div>
        </div>
      )}

      {uploadSuccess && (
        <div className="bg-green-50 border-l-4 border-green-600 p-4 mb-6">
          <div className="flex items-center">
            <Camera className="h-5 w-5 text-green-600 mr-2" />
            <p className="text-green-700">{uploadSuccess}</p>
          </div>
        </div>
      )}

      {/* Payment feedback handling for professionals */}
      {(() => {
        const urlParams = new URLSearchParams(window.location.search);
        const paymentStatus = urlParams.get("payment");

        if (paymentStatus === "success") {
          return (
            <div className="bg-green-50 border-l-4 border-green-600 p-4 mb-6">
              <div className="flex items-center">
                <CheckCircle className="h-5 w-5 text-green-600 mr-2" />
                <p className="text-green-700">
                  Pagamento ao convênio realizado com sucesso! O valor foi
                  registrado em seu histórico.
                </p>
              </div>
            </div>
          );
        } else if (paymentStatus === "failure") {
          return (
            <div className="bg-red-50 border-l-4 border-red-600 p-4 mb-6">
              <div className="flex items-center">
                <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
                <p className="text-red-700">
                  Falha no pagamento ao convênio. Tente novamente.
                </p>
              </div>
            </div>
          );
        } else if (paymentStatus === "pending") {
          return (
            <div className="bg-yellow-50 border-l-4 border-yellow-600 p-4 mb-6">
              <div className="flex items-center">
                <Clock className="h-5 w-5 text-yellow-600 mr-2" />
                <p className="text-yellow-700">
                  Pagamento ao convênio está sendo processado.
                </p>
              </div>
            </div>
          );
        }
        return null;
      })()}

      {error && (
        <div className="bg-red-50 border-l-4 border-red-600 p-4 mb-6">
          <div className="flex items-center">
            <AlertCircle className="h-5 w-5 text-red-600 mr-2" />
            <div>
              <p className="text-red-700 font-medium">Erro ao carregar dados</p>
              <p className="text-red-600 text-sm">{error}</p>
            </div>
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="text-center py-12">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
          <p className="text-gray-600">Carregando dados...</p>
        </div>
      ) : revenueReport ? (
        <>
          {/* Statistics Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">
                  Consultas Realizadas
                </h3>
                <Users className="h-5 w-5 text-blue-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {revenueReport.summary.consultation_count || 0}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Atendimentos realizados
              </p>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">
                  Faturamento Total
                </h3>
                <TrendingUp className="h-5 w-5 text-green-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {formatCurrency(revenueReport.summary.total_revenue || 0)}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                {revenueReport.summary.professional_percentage || 50}% é sua
                porcentagem
              </p>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-sm font-medium text-gray-600">
                  Contas a Pagar
                </h3>
                <DollarSign className="h-5 w-5 text-red-600" />
              </div>
              <p className="text-2xl font-bold text-gray-900">
                {formatCurrency(revenueReport.summary.amount_to_pay || 0)}
              </p>
              <p className="text-sm text-gray-500 mt-1">
                Valor a ser repassado ao convênio
              </p>
            </div>
          </div>

          {/* Payment Section */}
          {revenueReport.summary.amount_to_pay > 0 && (
            <PaymentSection amount={revenueReport.summary.amount_to_pay} />
          )}

          {/* Consultations Table */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <div className="flex items-center mb-6">
              <CalendarClock className="h-6 w-6 text-red-600 mr-2" />
              <h2 className="text-xl font-semibold">Consultas Realizadas</h2>
            </div>

            {!revenueReport.consultations ||
            revenueReport.consultations.length === 0 ? (
              <div className="text-center py-12 bg-gray-50 rounded-lg">
                <CalendarClock className="h-16 w-16 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                  Nenhuma consulta registrada
                </h3>
                <p className="text-gray-600 mb-4">
                  Você ainda não registrou nenhuma consulta este mês.
                </p>
                <Link
                  to="/professional/register-consultation"
                  className="btn btn-primary inline-flex items-center"
                >
                  <PlusCircle className="h-5 w-5 mr-2" />
                  Registrar Primeira Consulta
                </Link>
              </div>
            ) : (
              <ConsultationsTable
                consultations={revenueReport.consultations}
                formatDate={formatDate}
                formatCurrency={formatCurrency}
              />
            )}
          </div>
        </>
      ) : (
        <div className="text-center py-12 bg-gray-50 rounded-lg">
          <AlertCircle className="h-16 w-16 text-gray-400 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-900 mb-2">
            Dados não disponíveis
          </h3>
          <p className="text-gray-600 mb-4">
            Não foi possível carregar os dados do relatório.
          </p>
          <button
            onClick={handleRetry}
            className="btn btn-primary"
            disabled={isLoading}
          >
            {isLoading ? (
              <>
                <RefreshCw className="h-5 w-5 mr-2 animate-spin" />
                Carregando...
              </>
            ) : (
              <>
                <RefreshCw className="h-5 w-5 mr-2" />
                Tentar Novamente
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
};

export default ProfessionalHomePage;
