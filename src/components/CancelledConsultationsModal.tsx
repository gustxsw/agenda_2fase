import React, { useState, useEffect } from "react";
import {
  XCircle,
  Calendar,
  User,
  Users,
  Search,
  X,
  AlertCircle,
  MessageSquare,
  Clock,
  MapPin,
  RefreshCw,
} from "lucide-react";

type CancelledConsultation = {
  id: number;
  date: string;
  patient_name: string;
  service_name: string;
  professional_name: string;
  value: number;
  cancellation_reason: string | null;
  cancelled_at: string;
  cancelled_by_name: string;
  is_dependent: boolean;
  patient_type: "convenio" | "private";
  location_name: string | null;
};

type CancelledConsultationsModalProps = {
  isOpen: boolean;
  onClose: () => void;
  autoRefresh?: boolean;
};

const CancelledConsultationsModal: React.FC<
  CancelledConsultationsModalProps
> = ({ isOpen, onClose, autoRefresh = false }) => {
  const [cancelledConsultations, setCancelledConsultations] = useState<
    CancelledConsultation[]
  >([]);
  const [filteredConsultations, setFilteredConsultations] = useState<
    CancelledConsultation[]
  >([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [startDate, setStartDate] = useState(getDefaultStartDate());
  const [endDate, setEndDate] = useState(getDefaultEndDate());
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");

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

  // Get default date range (current month)
  function getDefaultStartDate() {
    const date = new Date();
    date.setDate(1); // First day of current month
    return date.toISOString().split("T")[0];
  }

  function getDefaultEndDate() {
    const date = new Date();
    return date.toISOString().split("T")[0];
  }

  useEffect(() => {
    if (isOpen) {
      fetchCancelledConsultations();
    }
  }, [isOpen]);

  useEffect(() => {
    if (autoRefresh && isOpen) {
      fetchCancelledConsultations();
    }
  }, [autoRefresh, isOpen]);

  useEffect(() => {
    let filtered = cancelledConsultations;

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(
        (consultation) =>
          consultation.patient_name
            .toLowerCase()
            .includes(searchTerm.toLowerCase()) ||
          consultation.service_name
            .toLowerCase()
            .includes(searchTerm.toLowerCase()) ||
          consultation.professional_name
            .toLowerCase()
            .includes(searchTerm.toLowerCase()) ||
          consultation.cancellation_reason
            ?.toLowerCase()
            .includes(searchTerm.toLowerCase())
      );
    }

    setFilteredConsultations(filtered);
  }, [cancelledConsultations, searchTerm]);

  const fetchCancelledConsultations = async () => {
    try {
      setIsLoading(true);
      setError("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      console.log("🔄 [MODAL-CANCEL] Fetching cancelled consultations");

      const response = await fetch(
        `${apiUrl}/api/reports/cancelled-consultations?start_date=${startDate}&end_date=${endDate}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          credentials: "include",
        }
      );

      console.log("📡 [MODAL-CANCEL] Response status:", response.status);

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error("Sessão expirada. Faça login novamente.");
        }
        const errorData = await response.json();
        console.error("❌ [MODAL-CANCEL] Error response:", errorData);
        throw new Error(
          errorData.message || "Erro ao carregar consultas canceladas"
        );
      }

      const data = await response.json();
      console.log(
        "✅ [MODAL-CANCEL] Cancelled consultations loaded:",
        data.length
      );
      setCancelledConsultations(data);
    } catch (error) {
      console.error(
        "❌ [MODAL-CANCEL] Error fetching cancelled consultations:",
        error
      );
      setError(
        error instanceof Error
          ? error.message
          : "Erro ao carregar consultas canceladas"
      );
      setCancelledConsultations([]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleDateRangeSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchCancelledConsultations();
  };

  const formatDate = (dateString: string) => {
    // Convert from UTC (database) to Brazil local time for display
    const cancelledUtcDate = new Date(dateString);
    const cancelledLocalDate = new Date(
      cancelledUtcDate.getTime() - 3 * 60 * 60 * 1000
    );
    return cancelledLocalDate.toLocaleDateString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
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

  const getPatientTypeDisplay = (consultation: CancelledConsultation) => {
    if (consultation.patient_type === "private") {
      return {
        icon: <User className="h-3 w-3 text-purple-600" />,
        label: "Particular",
        className: "bg-purple-100 text-purple-800",
      };
    } else if (consultation.is_dependent) {
      return {
        icon: <Users className="h-3 w-3 text-blue-600" />,
        label: "Dependente",
        className: "bg-blue-100 text-blue-800",
      };
    } else {
      return {
        icon: <User className="h-3 w-3 text-green-600" />,
        label: "Titular",
        className: "bg-green-100 text-green-800",
      };
    }
  };

  // Statistics
  const totalCancelled = cancelledConsultations.length;
  const totalValue = cancelledConsultations.reduce(
    (sum, c) => sum + c.value,
    0
  );
  const convenioCount = cancelledConsultations.filter(
    (c) => c.patient_type === "convenio"
  ).length;
  const privateCount = cancelledConsultations.filter(
    (c) => c.patient_type === "private"
  ).length;

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl w-full max-w-6xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-6 border-b border-gray-200 flex justify-between items-center bg-gray-50">
          <div className="flex items-center">
            <XCircle className="h-6 w-6 text-red-600 mr-3" />
            <div>
              <h2 className="text-xl font-bold text-gray-900">
                Consultas Canceladas
              </h2>
              <p className="text-sm text-gray-600">
                Histórico de consultas canceladas
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition-colors"
          >
            <X className="h-6 w-6" />
          </button>
        </div>

        {/* Date Range Filter */}
        <div className="p-6 border-b border-gray-200 bg-white">
          <form
            onSubmit={handleDateRangeSubmit}
            className="flex items-end space-x-4"
          >
            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Data Inicial
              </label>
              <input
                type="date"
                value={startDate}
                onChange={(e) => setStartDate(e.target.value)}
                className="input"
                required
              />
            </div>

            <div className="flex-1">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Data Final
              </label>
              <input
                type="date"
                value={endDate}
                onChange={(e) => setEndDate(e.target.value)}
                className="input"
                required
              />
            </div>

            <button
              type="submit"
              className={`btn btn-primary flex items-center ${
                isLoading ? "opacity-70 cursor-not-allowed" : ""
              }`}
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                  Carregando...
                </>
              ) : (
                "Filtrar"
              )}
            </button>
          </form>
        </div>

        {/* Statistics Cards */}
        <div className="p-6 border-b border-gray-200 bg-gray-50">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-white rounded-lg shadow-sm border border-gray-100 p-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">
                  {totalCancelled}
                </div>
                <div className="text-sm text-gray-600">Total Canceladas</div>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-sm border border-gray-100 p-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-green-600">
                  {convenioCount}
                </div>
                <div className="text-sm text-gray-600">Convênio</div>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-sm border border-gray-100 p-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-purple-600">
                  {privateCount}
                </div>
                <div className="text-sm text-gray-600">Particulares</div>
              </div>
            </div>
            <div className="bg-white rounded-lg shadow-sm border border-gray-100 p-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-gray-600">
                  {formatCurrency(totalValue)}
                </div>
                <div className="text-sm text-gray-600">Valor Total</div>
              </div>
            </div>
          </div>
        </div>

        {/* Search Filter */}
        <div className="p-6 border-b border-gray-200">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar por paciente, serviço, profissional ou motivo..."
              className="input pl-10"
            />
          </div>
        </div>

        {error && (
          <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg flex items-center">
            <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0" />
            {error}
          </div>
        )}

        {/* Cancelled Consultations Table */}
        <div className="flex-1 overflow-y-auto">
          {isLoading ? (
            <div className="text-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
              <p className="text-gray-600">
                Carregando consultas canceladas...
              </p>
            </div>
          ) : filteredConsultations.length === 0 ? (
            <div className="text-center py-12">
              <XCircle className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                {searchTerm
                  ? "Nenhuma consulta encontrada"
                  : "Nenhuma consulta cancelada"}
              </h3>
              <p className="text-gray-600">
                {searchTerm
                  ? "Tente ajustar os termos de busca."
                  : "Não há consultas canceladas no período selecionado."}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full">
                <thead className="bg-gray-50 sticky top-0">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Data da Consulta
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Paciente
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Serviço
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Profissional
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Valor
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Motivo
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                      Cancelado em
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {filteredConsultations.map((consultation) => {
                    const patientTypeInfo = getPatientTypeDisplay(consultation);

                    return (
                      <tr key={consultation.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center text-sm text-gray-900">
                            <Calendar className="h-4 w-4 text-gray-400 mr-2" />
                            {formatDate(consultation.date)}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            {patientTypeInfo.icon}
                            <div className="ml-2">
                              <div className="text-sm font-medium text-gray-900">
                                {consultation.patient_name}
                              </div>
                              <span
                                className={`px-2 py-1 text-xs font-medium rounded-full ${patientTypeInfo.className}`}
                              >
                                {patientTypeInfo.label}
                              </span>
                            </div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {consultation.service_name}
                          </div>
                          {consultation.location_name && (
                            <div className="text-xs text-gray-500 flex items-center mt-1">
                              <MapPin className="h-3 w-3 mr-1" />
                              {consultation.location_name}
                            </div>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900">
                            {consultation.professional_name}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm font-medium text-gray-900">
                            {formatCurrency(consultation.value)}
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="max-w-xs">
                            {consultation.cancellation_reason ? (
                              <div className="flex items-start">
                                <MessageSquare className="h-4 w-4 text-gray-400 mr-2 mt-0.5 flex-shrink-0" />
                                <div className="text-sm text-gray-600">
                                  {consultation.cancellation_reason}
                                </div>
                              </div>
                            ) : (
                              <span className="text-sm text-gray-400 italic">
                                Motivo não informado
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-500">
                            <div className="flex items-center">
                              <Clock className="h-3 w-3 mr-1" />
                              {formatDate(consultation.cancelled_at)}
                            </div>
                            <div className="text-xs text-gray-400 mt-1">
                              por {consultation.cancelled_by_name}
                            </div>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Summary Footer */}
        {filteredConsultations.length > 0 && (
          <div className="p-6 border-t border-gray-200 bg-red-50">
            <div className="flex items-center mb-2">
              <XCircle className="h-5 w-5 text-red-600 mr-2" />
              <h3 className="font-medium text-red-900">Resumo do Período</h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="font-medium text-red-800">Período:</span>
                <div className="text-red-700">
                  {new Date(startDate).toLocaleDateString("pt-BR")} a{" "}
                  {new Date(endDate).toLocaleDateString("pt-BR")}
                </div>
              </div>
              <div>
                <span className="font-medium text-red-800">
                  Total Canceladas:
                </span>
                <div className="text-red-700">
                  {filteredConsultations.length}
                </div>
              </div>
              <div>
                <span className="font-medium text-red-800">Valor Total:</span>
                <div className="text-red-700">{formatCurrency(totalValue)}</div>
              </div>
              <div>
                <span className="font-medium text-red-800">Com Motivo:</span>
                <div className="text-red-700">
                  {
                    cancelledConsultations.filter((c) => c.cancellation_reason)
                      .length
                  }{" "}
                  de {totalCancelled}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default CancelledConsultationsModal;
