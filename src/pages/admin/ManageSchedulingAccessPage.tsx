import type React from "react";
import { useState, useEffect } from "react";
import {
  UserCheck,
  Trash2,
  Search,
  Filter,
  Clock,
  Gift,
  AlertCircle,
  X,
  Check,
} from "lucide-react";

type Professional = {
  id: number;
  name: string;
  email: string;
  phone: string;
  category_name: string;
  has_scheduling_access: boolean;
  access_expires_at: string | null;
  access_granted_by: string | null;
  access_granted_at: string | null;
  access_reason: string | null;
};

const ManageSchedulingAccessPage: React.FC = () => {
  const [professionals, setProfessionals] = useState<Professional[]>([]);
  const [filteredProfessionals, setFilteredProfessionals] = useState<
    Professional[]
  >([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterStatus, setFilterStatus] = useState<string>("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<"grant" | "extend">("grant");
  const [selectedProfessional, setSelectedProfessional] =
    useState<Professional | null>(null);

  // Form state
  const [expiryDate, setExpiryDate] = useState("");
  const [reason, setReason] = useState("");

  // Delete confirmation state
  const [showRevokeConfirm, setShowRevokeConfirm] = useState(false);
  const [professionalToRevoke, setProfessionalToRevoke] =
    useState<Professional | null>(null);

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

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    let filtered = professionals;

    if (searchTerm) {
      filtered = filtered.filter(
        (prof) =>
          prof.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          prof.email?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (filterStatus) {
      if (filterStatus === "with_access") {
        filtered = filtered.filter((prof) => prof.has_scheduling_access);
      } else if (filterStatus === "without_access") {
        filtered = filtered.filter((prof) => !prof.has_scheduling_access);
      } else if (filterStatus === "expired_access") {
        filtered = filtered.filter(
          (prof) =>
            prof.has_scheduling_access &&
            prof.access_expires_at &&
            new Date(prof.access_expires_at) < new Date()
        );
      }
    }

    setFilteredProfessionals(filtered);
  }, [professionals, searchTerm, filterStatus]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError("");
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      console.log(
        "🔄 Fetching professionals scheduling access from:",
        `${apiUrl}/api/admin/professionals-scheduling-access`
      );

      // Fetch professionals with their scheduling access status
      const response = await fetch(
        `${apiUrl}/api/admin/professionals-scheduling-access`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      console.log("📡 Response status:", response.status);

      if (!response.ok) {
        const errorText = await response.text();
        console.error("❌ Response error:", errorText);
        throw new Error(`Falha ao carregar profissionais: ${response.status}`);
      }

      const data = await response.json();
      console.log("✅ Professionals data loaded:", data.length);
      setProfessionals(data);
    } catch (error) {
      console.error("Error fetching data:", error);
      setError(
        error instanceof Error
          ? error.message
          : "Não foi possível carregar os dados"
      );
      setProfessionals([]);
    } finally {
      setIsLoading(false);
    }
  };

  const openGrantModal = (professional: Professional) => {
    setModalMode("grant");
    setSelectedProfessional(professional);

    // Set default expiry to 7 days from now
    const defaultExpiry = new Date();
    defaultExpiry.setDate(defaultExpiry.getDate() + 7);
    setExpiryDate(defaultExpiry.toISOString().split("T")[0]);

    setReason("Acesso promocional para teste da agenda");
    setIsModalOpen(true);
  };

  const openExtendModal = (professional: Professional) => {
    setModalMode("extend");
    setSelectedProfessional(professional);

    // Set default expiry to 7 days from current expiry or now
    const currentExpiry = professional.access_expires_at
      ? new Date(professional.access_expires_at)
      : new Date();
    const defaultExpiry = new Date(currentExpiry);
    defaultExpiry.setDate(defaultExpiry.getDate() + 7);
    setExpiryDate(defaultExpiry.toISOString().split("T")[0]);

    setReason("Extensão do período de teste");
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setSelectedProfessional(null);
    setExpiryDate("");
    setReason("");
    setError("");
    setSuccess("");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    if (!selectedProfessional || !expiryDate) return;

    try {
      setIsLoading(true);
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      console.log("🔄 Granting/extending access:", {
        professional_id: selectedProfessional.id,
        expires_at: expiryDate,
        reason: reason,
      });

      const response = await fetch(
        `${apiUrl}/api/admin/grant-scheduling-access`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            professional_id: selectedProfessional.id,
            expires_at: expiryDate,
            reason: reason || null,
          }),
        }
      );

      console.log("📡 Grant access response status:", response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ Grant access error:", errorData);
        throw new Error(errorData.message || "Erro ao conceder acesso");
      }

      const responseData = await response.json();
      console.log("✅ Access granted successfully:", responseData);

      await fetchData();
      setSuccess(
        modalMode === "grant"
          ? "Acesso à agenda concedido com sucesso!"
          : "Acesso à agenda estendido com sucesso!"
      );

      setTimeout(() => {
        closeModal();
      }, 1500);
    } catch (error) {
      console.error("Error in handleSubmit:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao processar solicitação"
      );
    } finally {
      setIsLoading(false);
    }
  };

  const confirmRevoke = (professional: Professional) => {
    setProfessionalToRevoke(professional);
    setShowRevokeConfirm(true);
  };

  const cancelRevoke = () => {
    setProfessionalToRevoke(null);
    setShowRevokeConfirm(false);
  };

  const revokeAccess = async () => {
    if (!professionalToRevoke) return;

    try {
      setIsLoading(true);
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      console.log(
        "🔄 Revoking access for professional:",
        professionalToRevoke.id
      );

      const response = await fetch(
        `${apiUrl}/api/admin/revoke-scheduling-access`,
        {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            professional_id: professionalToRevoke.id,
          }),
        }
      );

      console.log("📡 Revoke access response status:", response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ Revoke access error:", errorData);
        throw new Error(errorData.message || "Erro ao revogar acesso");
      }

      console.log("✅ Access revoked successfully");
      await fetchData();
      setSuccess("Acesso à agenda revogado com sucesso!");
    } catch (error) {
      console.error("Error in revokeAccess:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao revogar acesso"
      );
    } finally {
      setIsLoading(false);
      setProfessionalToRevoke(null);
      setShowRevokeConfirm(false);
    }
  };

  const formatDate = (dateString: string) => {
    // Convert from UTC (database) to Brazil local time for display
    const accessUtcDate = new Date(dateString);
    const accessLocalDate = new Date(
      accessUtcDate.getTime() - 3 * 60 * 60 * 1000
    );
    return accessLocalDate.toLocaleDateString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
    });
  };

  const formatDateTime = (dateString: string) => {
    // Convert from UTC (database) to Brazil local time for display
    const accessDateTimeUtcDate = new Date(dateString);
    const accessDateTimeLocalDate = new Date(
      accessDateTimeUtcDate.getTime() - 3 * 60 * 60 * 1000
    );
    return accessDateTimeLocalDate.toLocaleDateString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const getAccessStatusDisplay = (professional: Professional) => {
    if (!professional.has_scheduling_access) {
      return {
        text: "Sem Acesso",
        className: "bg-gray-100 text-gray-800",
        icon: null,
      };
    }

    if (professional.access_expires_at) {
      const expiryDate = new Date(professional.access_expires_at);
      const now = new Date();

      if (expiryDate < now) {
        return {
          text: "Acesso Expirado",
          className: "bg-red-100 text-red-800",
          icon: <AlertCircle className="h-3 w-3 mr-1" />,
        };
      } else {
        return {
          text: "Acesso Ativo",
          className: "bg-green-100 text-green-800",
          icon: <Gift className="h-3 w-3 mr-1" />,
        };
      }
    }

    return {
      text: "Acesso Ativo",
      className: "bg-green-100 text-green-800",
      icon: <Gift className="h-3 w-3 mr-1" />,
    };
  };

  const resetFilters = () => {
    setSearchTerm("");
    setFilterStatus("");
  };

  const activeAccessCount = professionals.filter(
    (p) =>
      p.has_scheduling_access &&
      (!p.access_expires_at || new Date(p.access_expires_at) > new Date())
  ).length;

  const expiredAccessCount = professionals.filter(
    (p) =>
      p.has_scheduling_access &&
      p.access_expires_at &&
      new Date(p.access_expires_at) < new Date()
  ).length;

  const noAccessCount = professionals.filter(
    (p) => !p.has_scheduling_access
  ).length;

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            Gerenciar Acesso à Agenda
          </h1>
          <p className="text-gray-600">
            Conceda acesso promocional à agenda (7 dias grátis) para campanhas
            de marketing.
            <span className="font-medium text-red-600">
              Valor mensal: R$ 24,99
            </span>
          </p>
        </div>
      </div>

      {/* Marketing Info Banner */}
      <div className="bg-gradient-to-r from-green-50 to-blue-50 border border-green-200 rounded-xl p-6 mb-6">
        <div className="flex items-start">
          <Gift className="h-6 w-6 text-green-600 mr-3 mt-1 flex-shrink-0" />
          <div className="flex-1">
            <h3 className="text-lg font-semibold text-green-900 mb-2">
              🎯 Estratégia de Marketing - Agenda Gratuita
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
              <div>
                <h4 className="font-medium text-green-800 mb-1">
                  Como Funciona:
                </h4>
                <ul className="text-green-700 space-y-1">
                  <li>
                    • Profissionais começam <strong>sem acesso</strong> à agenda
                  </li>
                  <li>
                    • Admin concede <strong>7 dias gratuitos</strong> para teste
                  </li>
                  <li>
                    • Após expirar, profissional paga{" "}
                    <strong>R$ 24,99/mês</strong>
                  </li>
                  <li>• Admin pode estender período promocional</li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium text-blue-800 mb-1">
                  Benefícios da Estratégia:
                </h4>
                <ul className="text-blue-700 space-y-1">
                  <li>• Atrai novos profissionais com teste grátis</li>
                  <li>• Demonstra valor da ferramenta</li>
                  <li>• Gera receita recorrente após teste</li>
                  <li>• Controle total sobre campanhas</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="flex items-center mb-4">
          <Filter className="h-5 w-5 text-red-600 mr-2" />
          <h2 className="text-lg font-semibold">Filtros</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar por nome ou email..."
              className="w-full pl-12 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
            />
          </div>

          <select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            className="input"
          >
            <option value="">Todos os profissionais</option>
            <option value="with_access">Com acesso à agenda</option>
            <option value="without_access">Sem acesso à agenda</option>
            <option value="expired_access">Acesso expirado</option>
          </select>

          <button onClick={resetFilters} className="btn btn-secondary">
            Limpar Filtros
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6">
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-50 text-green-600 p-4 rounded-lg mb-6">
          {success}
        </div>
      )}

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-6">
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-600">
              Total de Profissionais
            </h3>
            <UserCheck className="h-5 w-5 text-blue-600" />
          </div>
          <p className="text-2xl font-bold text-gray-900">
            {professionals.length}
          </p>
          <p className="text-xs text-gray-500 mt-1">Cadastrados no sistema</p>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-600">
              Com Acesso Ativo
            </h3>
            <Gift className="h-5 w-5 text-green-600" />
          </div>
          <p className="text-2xl font-bold text-gray-900">
            {activeAccessCount}
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Usando agenda gratuitamente
          </p>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-600">
              Acesso Expirado
            </h3>
            <AlertCircle className="h-5 w-5 text-red-600" />
          </div>
          <p className="text-2xl font-bold text-gray-900">
            {expiredAccessCount}
          </p>
          <p className="text-xs text-gray-500 mt-1">
            Podem assinar por R$ 24,99/mês
          </p>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-medium text-gray-600">Sem Acesso</h3>
            <Clock className="h-5 w-5 text-gray-600" />
          </div>
          <p className="text-2xl font-bold text-gray-900">{noAccessCount}</p>
          <p className="text-xs text-gray-500 mt-1">
            Potenciais novos usuários
          </p>
        </div>
      </div>

      {/* Professionals Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando profissionais...</p>
          </div>
        ) : filteredProfessionals.length === 0 ? (
          <div className="text-center py-12">
            <UserCheck className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {searchTerm || filterStatus
                ? "Nenhum profissional encontrado"
                : "Nenhum profissional cadastrado"}
            </h3>
            <p className="text-gray-600">
              {searchTerm || filterStatus
                ? "Tente ajustar os filtros de busca."
                : "Cadastre profissionais primeiro para gerenciar o acesso à agenda."}
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Profissional
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Categoria
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status do Acesso
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Expira em
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Concedido por
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ações
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredProfessionals.map((professional) => {
                  const statusInfo = getAccessStatusDisplay(professional);
                  return (
                    <tr key={professional.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="flex-shrink-0 h-10 w-10">
                            <div className="h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                              <UserCheck className="h-5 w-5 text-red-600" />
                            </div>
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">
                              {professional.name}
                            </div>
                            {professional.email && (
                              <div className="text-sm text-gray-500">
                                {professional.email}
                              </div>
                            )}
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="text-sm text-gray-900">
                          {professional.category_name || "Sem categoria"}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`px-2 py-1 text-xs font-medium rounded-full flex items-center w-fit ${statusInfo.className}`}
                        >
                          {statusInfo.icon}
                          {statusInfo.text}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {professional.access_expires_at
                          ? formatDate(professional.access_expires_at)
                          : "-"}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {professional.access_granted_by || "-"}
                        {professional.access_reason && (
                          <div className="text-xs text-gray-400 mt-1">
                            {professional.access_reason}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end space-x-2">
                          {!professional.has_scheduling_access ? (
                            <button
                              onClick={() => openGrantModal(professional)}
                              className="text-green-600 hover:text-green-900 flex items-center px-3 py-1 bg-green-50 rounded-lg hover:bg-green-100 transition-colors"
                              title="Conceder Acesso"
                              disabled={isLoading}
                            >
                              <Gift className="h-4 w-4 mr-1" />
                              Conceder 7 dias
                            </button>
                          ) : (
                            <>
                              {/* Check if access is expired */}
                              {professional.access_expires_at &&
                              new Date(professional.access_expires_at) <
                                new Date() ? (
                                <button
                                  onClick={() => openGrantModal(professional)}
                                  className="text-green-600 hover:text-green-900 flex items-center px-3 py-1 bg-green-50 rounded-lg hover:bg-green-100 transition-colors"
                                  title="Renovar Acesso"
                                  disabled={isLoading}
                                >
                                  <Gift className="h-4 w-4 mr-1" />
                                  Renovar
                                </button>
                              ) : (
                                <button
                                  onClick={() => openExtendModal(professional)}
                                  className="text-blue-600 hover:text-blue-900 flex items-center px-2 py-1 bg-blue-50 rounded-lg hover:bg-blue-100 transition-colors"
                                  title="Estender Acesso"
                                  disabled={isLoading}
                                >
                                  <Clock className="h-4 w-4 mr-1" />
                                  Estender
                                </button>
                              )}
                              <button
                                onClick={() => confirmRevoke(professional)}
                                className="text-red-600 hover:text-red-900 flex items-center px-2 py-1 bg-red-50 rounded-lg hover:bg-red-100 transition-colors"
                                title="Revogar Acesso"
                                disabled={isLoading}
                              >
                                <Trash2 className="h-4 w-4 mr-1" />
                                Revogar
                              </button>
                            </>
                          )}
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

      {/* Grant/Extend Access Modal */}
      {isModalOpen && selectedProfessional && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold flex items-center">
                <Gift className="h-6 w-6 text-green-600 mr-2" />
                {modalMode === "grant"
                  ? "Conceder Acesso à Agenda"
                  : "Estender Acesso à Agenda"}
              </h2>
            </div>

            {error && (
              <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg">
                {error}
              </div>
            )}

            {success && (
              <div className="mx-6 mt-4 bg-green-50 text-green-600 p-3 rounded-lg">
                {success}
              </div>
            )}

            <form onSubmit={handleSubmit} className="p-6">
              <div className="mb-4">
                <p className="text-gray-700 mb-2">
                  <span className="font-medium">Profissional:</span>{" "}
                  {selectedProfessional.name}
                </p>
                <p className="text-gray-700 mb-4">
                  <span className="font-medium">Categoria:</span>{" "}
                  {selectedProfessional.category_name}
                </p>

                {modalMode === "extend" &&
                  selectedProfessional.access_expires_at && (
                    <p className="text-gray-700 mb-4">
                      <span className="font-medium">Expira atualmente em:</span>{" "}
                      {formatDate(selectedProfessional.access_expires_at)}
                    </p>
                  )}
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    {modalMode === "grant"
                      ? "Data de Expiração (7 dias padrão) *"
                      : "Nova Data de Expiração *"}
                  </label>
                  <input
                    type="date"
                    value={expiryDate}
                    onChange={(e) => setExpiryDate(e.target.value)}
                    className="input"
                    min={new Date().toISOString().split("T")[0]}
                    required
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    {modalMode === "grant"
                      ? "Período promocional gratuito de 7 dias para teste"
                      : "Estender o período de acesso gratuito"}
                  </p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Motivo da Concessão/Extensão
                  </label>
                  <textarea
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    className="input min-h-[80px]"
                    placeholder={
                      modalMode === "grant"
                        ? "Ex: Campanha de marketing, profissional em teste, parceria especial..."
                        : "Ex: Extensão por bom desempenho, parceria especial..."
                    }
                    required
                  />
                  <p className="text-xs text-gray-500 mt-1">
                    Este motivo será registrado no histórico de acesso
                  </p>
                </div>
              </div>

              <div className="bg-blue-50 p-4 rounded-lg mt-4 mb-4">
                <h4 className="font-medium text-blue-900 mb-2">
                  🎁 Acesso Promocional Gratuito - O que está incluído:
                </h4>
                <ul className="text-sm text-blue-700 space-y-1">
                  <li>• Acesso completo ao sistema de agendamentos</li>
                  <li>• Gestão de pacientes particulares</li>
                  <li>• Prontuários médicos digitais</li>
                  <li>• Geração de documentos médicos</li>
                  <li>• Relatórios detalhados</li>
                  <li>
                    • <strong>Período de teste: 7 dias gratuitos</strong>
                  </li>
                  <li>
                    • <strong>Após o período: R$ 24,99/mês</strong>
                  </li>
                </ul>

                <div className="mt-3 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                  <p className="text-xs text-yellow-700">
                    <strong>💡 Estratégia de Marketing:</strong> Use este acesso
                    gratuito para demonstrar o valor da agenda aos
                    profissionais. Após 7 dias, eles podem assinar por R$
                    24,99/mês.
                  </p>
                </div>
              </div>

              <div className="flex justify-end space-x-3 pt-4 border-t border-gray-200">
                <button
                  type="button"
                  onClick={closeModal}
                  className="btn btn-secondary"
                  disabled={isLoading}
                >
                  Cancelar
                </button>
                <button
                  type="submit"
                  className={`btn btn-primary flex items-center ${
                    isLoading ? "opacity-70 cursor-not-allowed" : ""
                  }`}
                  disabled={isLoading}
                >
                  {isLoading ? (
                    <>
                      <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                      Processando...
                    </>
                  ) : (
                    <>
                      <Gift className="h-5 w-5 mr-2" />
                      {modalMode === "grant"
                        ? "Conceder Acesso"
                        : "Estender Acesso"}
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Revoke confirmation modal */}
      {showRevokeConfirm && professionalToRevoke && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <h2 className="text-xl font-bold mb-4 flex items-center">
                <AlertCircle className="h-6 w-6 text-red-600 mr-2" />
                Confirmar Revogação
              </h2>

              <p className="mb-6">
                Tem certeza que deseja revogar o acesso à agenda do profissional{" "}
                <strong>{professionalToRevoke.name}</strong>?
              </p>

              <div className="bg-yellow-50 p-3 rounded-lg mb-6">
                <p className="text-yellow-700 text-sm">
                  <strong>Atenção:</strong> Esta ação irá:
                </p>
                <ul className="text-yellow-700 text-sm mt-2 list-disc list-inside">
                  <li>Revogar imediatamente o acesso à agenda</li>
                  <li>Manter acesso aos outros recursos do sistema</li>
                  <li>
                    Permitir que o profissional assine a agenda por R$ 24,99/mês
                  </li>
                  <li>Preservar todos os dados já cadastrados</li>
                </ul>
              </div>

              <div className="flex justify-end space-x-3">
                <button
                  onClick={cancelRevoke}
                  className="btn btn-secondary flex items-center"
                  disabled={isLoading}
                >
                  <X className="h-4 w-4 mr-2" />
                  Cancelar
                </button>
                <button
                  onClick={revokeAccess}
                  className={`btn bg-red-600 text-white hover:bg-red-700 flex items-center ${
                    isLoading ? "opacity-70 cursor-not-allowed" : ""
                  }`}
                  disabled={isLoading}
                >
                  {isLoading ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                      Processando...
                    </>
                  ) : (
                    <>
                      <Check className="h-4 w-4 mr-2" />
                      Revogar Acesso
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ManageSchedulingAccessPage;
