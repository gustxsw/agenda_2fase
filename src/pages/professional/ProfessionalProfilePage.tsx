import React, { useState, useEffect } from "react";
import { useAuth } from "../../contexts/AuthContext";
import {
  User,
  MapPin,
  Plus,
  Edit,
  Trash2,
  Eye,
  EyeOff,
  Save,
  X,
  Check,
  FileImage,
  Upload,
} from "lucide-react";
import UploadSignatureModal from "../../components/UploadSignatureModal";

type AttendanceLocation = {
  id: number;
  name: string;
  address: string;
  address_number: string;
  address_complement: string;
  neighborhood: string;
  city: string;
  state: string;
  zip_code: string;
  phone: string;
  is_default: boolean;
};

const ProfessionalProfilePage: React.FC = () => {
  const { user } = useAuth();
  const [locations, setLocations] = useState<AttendanceLocation[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Profile form state
  const [profileData, setProfileData] = useState({
    name: "",
    email: "",
    phone: "",
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });

  // Location modal state
  const [isLocationModalOpen, setIsLocationModalOpen] = useState(false);
  const [locationModalMode, setLocationModalMode] = useState<"create" | "edit">(
    "create"
  );
  const [selectedLocation, setSelectedLocation] =
    useState<AttendanceLocation | null>(null);

  // Location form state
  const [locationData, setLocationData] = useState({
    name: "",
    address: "",
    address_number: "",
    address_complement: "",
    neighborhood: "",
    city: "",
    state: "",
    zip_code: "",
    phone: "",
    is_default: false,
  });

  // Password visibility
  const [showCurrentPassword, setShowCurrentPassword] = useState(false);
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  // Delete confirmation
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [locationToDelete, setLocationToDelete] =
    useState<AttendanceLocation | null>(null);

  // Signature state
  const [signatureUrl, setSignatureUrl] = useState<string | null>(null);
  const [showSignatureModal, setShowSignatureModal] = useState(false);

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

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      // Fetch user profile
      const userResponse = await fetch(`${apiUrl}/api/users/${user?.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (userResponse.ok) {
        const userData = await userResponse.json();
        setProfileData((prev) => ({
          ...prev,
          name: userData.name || "",
          email: userData.email || "",
          phone: userData.phone || "",
        }));
      }

      // Fetch attendance locations
      const locationsResponse = await fetch(
        `${apiUrl}/api/attendance-locations`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (locationsResponse.ok) {
        const locationsData = await locationsResponse.json();
        setLocations(locationsData);
      }

      // Fetch signature
      const signatureResponse = await fetch(
        `${apiUrl}/api/professionals/${user?.id}/signature`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (signatureResponse.ok) {
        const signatureData = await signatureResponse.json();
        setSignatureUrl(signatureData.signature_url);
      }
    } catch (error) {
      console.error("Error fetching data:", error);
      setError("Não foi possível carregar os dados");
    } finally {
      setIsLoading(false);
    }
  };

  const handleProfileSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    // Validate password change
    if (profileData.newPassword) {
      if (!profileData.currentPassword) {
        setError("Senha atual é obrigatória para alterar a senha");
        return;
      }
      if (profileData.newPassword !== profileData.confirmPassword) {
        setError("Nova senha e confirmação não coincidem");
        return;
      }
      if (profileData.newPassword.length < 6) {
        setError("Nova senha deve ter pelo menos 6 caracteres");
        return;
      }
    }

    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const updateData: any = {
        name: profileData.name,
        email: profileData.email,
        phone: profileData.phone,
      };

      if (profileData.newPassword) {
        updateData.currentPassword = profileData.currentPassword;
        updateData.newPassword = profileData.newPassword;
      }

      const response = await fetch(`${apiUrl}/api/users/${user?.id}`, {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(updateData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao atualizar perfil");
      }

      setSuccess("Perfil atualizado com sucesso!");

      // Clear password fields
      setProfileData((prev) => ({
        ...prev,
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
      }));
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Erro ao atualizar perfil"
      );
    }
  };

  const openLocationModal = (
    mode: "create" | "edit",
    location?: AttendanceLocation
  ) => {
    setLocationModalMode(mode);

    if (mode === "edit" && location) {
      setLocationData({
        name: location.name,
        address: location.address || "",
        address_number: location.address_number || "",
        address_complement: location.address_complement || "",
        neighborhood: location.neighborhood || "",
        city: location.city || "",
        state: location.state || "",
        zip_code: location.zip_code || "",
        phone: location.phone || "",
        is_default: location.is_default,
      });
      setSelectedLocation(location);
    } else {
      setLocationData({
        name: "",
        address: "",
        address_number: "",
        address_complement: "",
        neighborhood: "",
        city: "",
        state: "",
        zip_code: "",
        phone: "",
        is_default: false,
      });
      setSelectedLocation(null);
    }

    setIsLocationModalOpen(true);
  };

  const closeLocationModal = () => {
    setIsLocationModalOpen(false);
    setError("");
    setSuccess("");
  };

  const handleLocationSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const url =
        locationModalMode === "create"
          ? `${apiUrl}/api/attendance-locations`
          : `${apiUrl}/api/attendance-locations/${selectedLocation?.id}`;

      const method = locationModalMode === "create" ? "POST" : "PUT";

      const response = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(locationData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao salvar local");
      }

      setSuccess(
        locationModalMode === "create"
          ? "Local criado com sucesso!"
          : "Local atualizado com sucesso!"
      );
      await fetchData();

      setTimeout(() => {
        closeLocationModal();
      }, 1500);
    } catch (error) {
      setError(error instanceof Error ? error.message : "Erro ao salvar local");
    }
  };

  const confirmDeleteLocation = (location: AttendanceLocation) => {
    setLocationToDelete(location);
    setShowDeleteConfirm(true);
  };

  const cancelDeleteLocation = () => {
    setLocationToDelete(null);
    setShowDeleteConfirm(false);
  };

  const deleteLocation = async () => {
    if (!locationToDelete) return;

    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const response = await fetch(
        `${apiUrl}/api/attendance-locations/${locationToDelete.id}`,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao excluir local");
      }

      await fetchData();
      setSuccess("Local excluído com sucesso!");
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Erro ao excluir local"
      );
    } finally {
      setLocationToDelete(null);
      setShowDeleteConfirm(false);
    }
  };

  const handleSignatureSuccess = () => {
    // Refresh signature data
    fetchData();
  };

  const formatZipCode = (value: string) => {
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 8);
    return limitedValue.replace(/(\d{5})(\d{3})/, "$1-$2");
  };

  const formatPhone = (value: string) => {
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 11);

    if (limitedValue.length <= 10) {
      return limitedValue.replace(/(\d{2})(\d{4})(\d{4})/, "($1) $2-$3");
    } else {
      return limitedValue.replace(/(\d{2})(\d{5})(\d{4})/, "($1) $2-$3");
    }
  };

  return (
    <div>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">
          Perfil Profissional
        </h1>
        <p className="text-gray-600">
          Gerencie suas informações pessoais e locais de atendimento
        </p>
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

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Profile Information */}
        <div className="space-y-6">
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <div className="flex items-center mb-6">
              <User className="h-6 w-6 text-red-600 mr-2" />
              <h2 className="text-xl font-semibold">Informações Pessoais</h2>
            </div>

            <form onSubmit={handleProfileSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Nome Completo
                </label>
                <input
                  type="text"
                  value={profileData.name}
                  onChange={(e) =>
                    setProfileData((prev) => ({
                      ...prev,
                      name: e.target.value,
                    }))
                  }
                  className="input"
                  required
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  value={profileData.email}
                  onChange={(e) =>
                    setProfileData((prev) => ({
                      ...prev,
                      email: e.target.value,
                    }))
                  }
                  className="input"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Telefone
                </label>
                <input
                  type="text"
                  value={profileData.phone}
                  onChange={(e) =>
                    setProfileData((prev) => ({
                      ...prev,
                      phone: formatPhone(e.target.value),
                    }))
                  }
                  className="input"
                  placeholder="(00) 00000-0000"
                />
              </div>

              <div className="border-t border-gray-200 pt-4">
                <h3 className="text-lg font-semibold text-gray-900 mb-4">
                  Alterar Senha
                </h3>

                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Senha Atual
                    </label>
                    <div className="relative">
                      <input
                        type={showCurrentPassword ? "text" : "password"}
                        value={profileData.currentPassword}
                        onChange={(e) =>
                          setProfileData((prev) => ({
                            ...prev,
                            currentPassword: e.target.value,
                          }))
                        }
                        className="input pr-10"
                      />
                      <button
                        type="button"
                        onClick={() =>
                          setShowCurrentPassword(!showCurrentPassword)
                        }
                        className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                      >
                        {showCurrentPassword ? (
                          <EyeOff className="h-5 w-5" />
                        ) : (
                          <Eye className="h-5 w-5" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Nova Senha
                    </label>
                    <div className="relative">
                      <input
                        type={showNewPassword ? "text" : "password"}
                        value={profileData.newPassword}
                        onChange={(e) =>
                          setProfileData((prev) => ({
                            ...prev,
                            newPassword: e.target.value,
                          }))
                        }
                        className="input pr-10"
                        minLength={6}
                      />
                      <button
                        type="button"
                        onClick={() => setShowNewPassword(!showNewPassword)}
                        className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                      >
                        {showNewPassword ? (
                          <EyeOff className="h-5 w-5" />
                        ) : (
                          <Eye className="h-5 w-5" />
                        )}
                      </button>
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Confirmar Nova Senha
                    </label>
                    <div className="relative">
                      <input
                        type={showConfirmPassword ? "text" : "password"}
                        value={profileData.confirmPassword}
                        onChange={(e) =>
                          setProfileData((prev) => ({
                            ...prev,
                            confirmPassword: e.target.value,
                          }))
                        }
                        className="input pr-10"
                        minLength={6}
                      />
                      <button
                        type="button"
                        onClick={() =>
                          setShowConfirmPassword(!showConfirmPassword)
                        }
                        className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                      >
                        {showConfirmPassword ? (
                          <EyeOff className="h-5 w-5" />
                        ) : (
                          <Eye className="h-5 w-5" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              <div className="flex justify-end pt-4">
                <button
                  type="submit"
                  className="btn btn-primary flex items-center"
                >
                  <Save className="h-5 w-5 mr-2" />
                  Salvar Alterações
                </button>
              </div>
            </form>
          </div>

          {/* Digital Signature Section */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center">
                <FileImage className="h-6 w-6 text-red-600 mr-2" />
                <h2 className="text-xl font-semibold">Assinatura Digital</h2>
              </div>

              <button
                onClick={() => setShowSignatureModal(true)}
                className="btn btn-primary flex items-center"
              >
                <Upload className="h-5 w-5 mr-2" />
                {signatureUrl ? "Alterar Assinatura" : "Adicionar Assinatura"}
              </button>
            </div>

            {signatureUrl ? (
              <div className="text-center">
                <div className="bg-gray-50 border border-gray-200 rounded-lg p-4 mb-4">
                  <img
                    src={signatureUrl}
                    alt="Sua assinatura digital"
                    className="max-w-full max-h-24 mx-auto border border-gray-300 rounded bg-white"
                    style={{ maxHeight: "96px" }}
                  />
                </div>
                <p className="text-sm text-gray-600">
                  Esta assinatura será incluída automaticamente em todos os
                  documentos que você gerar.
                </p>
              </div>
            ) : (
              <div className="text-center py-8 bg-gray-50 rounded-lg">
                <FileImage className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 mb-2">
                  Nenhuma assinatura cadastrada
                </h3>
                <p className="text-gray-600 mb-4">
                  Adicione sua assinatura digital para que ela apareça
                  automaticamente nos documentos gerados.
                </p>
                <button
                  onClick={() => setShowSignatureModal(true)}
                  className="btn btn-primary inline-flex items-center"
                >
                  <Upload className="h-5 w-5 mr-2" />
                  Adicionar Assinatura
                </button>
              </div>
            )}

            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mt-4">
              <h4 className="font-medium text-blue-900 mb-2">
                💡 Como funciona:
              </h4>
              <ul className="text-sm text-blue-700 space-y-1">
                <li>• Faça upload de uma imagem da sua assinatura</li>
                <li>
                  • A assinatura será incluída automaticamente em atestados,
                  receitas e outros documentos
                </li>
                <li>
                  • Você pode alterar ou remover a assinatura a qualquer momento
                </li>
                <li>• Use uma imagem com fundo branco para melhor resultado</li>
              </ul>
            </div>
          </div>
        </div>

        {/* Attendance Locations */}
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center">
              <MapPin className="h-6 w-6 text-red-600 mr-2" />
              <h2 className="text-xl font-semibold">Locais de Atendimento</h2>
            </div>

            <button
              onClick={() => openLocationModal("create")}
              className="btn btn-primary flex items-center"
            >
              <Plus className="h-5 w-5 mr-2" />
              Novo Local
            </button>
          </div>

          {isLoading ? (
            <div className="text-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-600 mx-auto mb-4"></div>
              <p className="text-gray-600">Carregando...</p>
            </div>
          ) : locations.length === 0 ? (
            <div className="text-center py-8 bg-gray-50 rounded-lg">
              <MapPin className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">
                Nenhum local cadastrado
              </h3>
              <p className="text-gray-600 mb-4">
                Adicione seus locais de atendimento
              </p>
              <button
                onClick={() => openLocationModal("create")}
                className="btn btn-primary inline-flex items-center"
              >
                <Plus className="h-5 w-5 mr-2" />
                Adicionar Primeiro Local
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {locations.map((location) => (
                <div
                  key={location.id}
                  className={`p-4 rounded-lg border-2 transition-colors ${
                    location.is_default
                      ? "border-red-200 bg-red-50"
                      : "border-gray-200 bg-gray-50"
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center mb-2">
                        <h3 className="font-semibold text-gray-900">
                          {location.name}
                        </h3>
                        {location.is_default && (
                          <span className="ml-2 px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs font-medium">
                            Padrão
                          </span>
                        )}
                      </div>

                      <div className="text-sm text-gray-600 space-y-1">
                        {location.address && (
                          <p>
                            {location.address}
                            {location.address_number &&
                              `, ${location.address_number}`}
                            {location.address_complement &&
                              `, ${location.address_complement}`}
                          </p>
                        )}
                        {location.neighborhood && location.city && (
                          <p>
                            {location.neighborhood}, {location.city} -{" "}
                            {location.state}
                          </p>
                        )}
                        {location.zip_code && (
                          <p>CEP: {formatZipCode(location.zip_code)}</p>
                        )}
                        {location.phone && (
                          <p>Telefone: {formatPhone(location.phone)}</p>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center space-x-2 ml-4">
                      <button
                        onClick={() => openLocationModal("edit", location)}
                        className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg"
                        title="Editar"
                      >
                        <Edit className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => confirmDeleteLocation(location)}
                        className="p-2 text-red-600 hover:bg-red-50 rounded-lg"
                        title="Excluir"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Location form modal */}
      {isLocationModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">
                {locationModalMode === "create"
                  ? "Novo Local de Atendimento"
                  : "Editar Local de Atendimento"}
              </h2>
            </div>

            <form onSubmit={handleLocationSubmit} className="p-6">
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Nome do Local *
                  </label>
                  <input
                    type="text"
                    value={locationData.name}
                    onChange={(e) =>
                      setLocationData((prev) => ({
                        ...prev,
                        name: e.target.value,
                      }))
                    }
                    className="input"
                    placeholder="Ex: Clínica Central"
                    required
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      CEP
                    </label>
                    <input
                      type="text"
                      value={locationData.zip_code}
                      onChange={(e) =>
                        setLocationData((prev) => ({
                          ...prev,
                          zip_code: e.target.value
                            .replace(/\D/g, "")
                            .slice(0, 8),
                        }))
                      }
                      className="input"
                      placeholder="00000-000"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Endereço
                    </label>
                    <input
                      type="text"
                      value={locationData.address}
                      onChange={(e) =>
                        setLocationData((prev) => ({
                          ...prev,
                          address: e.target.value,
                        }))
                      }
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Número
                    </label>
                    <input
                      type="text"
                      value={locationData.address_number}
                      onChange={(e) =>
                        setLocationData((prev) => ({
                          ...prev,
                          address_number: e.target.value,
                        }))
                      }
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Complemento
                    </label>
                    <input
                      type="text"
                      value={locationData.address_complement}
                      onChange={(e) =>
                        setLocationData((prev) => ({
                          ...prev,
                          address_complement: e.target.value,
                        }))
                      }
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Bairro
                    </label>
                    <input
                      type="text"
                      value={locationData.neighborhood}
                      onChange={(e) =>
                        setLocationData((prev) => ({
                          ...prev,
                          neighborhood: e.target.value,
                        }))
                      }
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Cidade
                    </label>
                    <input
                      type="text"
                      value={locationData.city}
                      onChange={(e) =>
                        setLocationData((prev) => ({
                          ...prev,
                          city: e.target.value,
                        }))
                      }
                      className="input"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Estado
                    </label>
                    <select
                      value={locationData.state}
                      onChange={(e) =>
                        setLocationData((prev) => ({
                          ...prev,
                          state: e.target.value,
                        }))
                      }
                      className="input"
                    >
                      <option value="">Selecione...</option>
                      <option value="AC">Acre</option>
                      <option value="AL">Alagoas</option>
                      <option value="AP">Amapá</option>
                      <option value="AM">Amazonas</option>
                      <option value="BA">Bahia</option>
                      <option value="CE">Ceará</option>
                      <option value="DF">Distrito Federal</option>
                      <option value="ES">Espírito Santo</option>
                      <option value="GO">Goiás</option>
                      <option value="MA">Maranhão</option>
                      <option value="MT">Mato Grosso</option>
                      <option value="MS">Mato Grosso do Sul</option>
                      <option value="MG">Minas Gerais</option>
                      <option value="PA">Pará</option>
                      <option value="PB">Paraíba</option>
                      <option value="PR">Paraná</option>
                      <option value="PE">Pernambuco</option>
                      <option value="PI">Piauí</option>
                      <option value="RJ">Rio de Janeiro</option>
                      <option value="RN">Rio Grande do Norte</option>
                      <option value="RS">Rio Grande do Sul</option>
                      <option value="RO">Rondônia</option>
                      <option value="RR">Roraima</option>
                      <option value="SC">Santa Catarina</option>
                      <option value="SP">São Paulo</option>
                      <option value="SE">Sergipe</option>
                      <option value="TO">Tocantins</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Registro Profissional
                    </label>
                    <input
                      type="text"
                      value={locationData.phone}
                      onChange={(e) =>
                        setLocationData((prev) => ({
                          ...prev,
                          phone: formatPhone(e.target.value),
                        }))
                      }
                      className="input"
                      placeholder="Ex: CREFITO 12345/GO, CRM 12345/GO"
                    />
                  </div>
                </div>

                <div>
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={locationData.is_default}
                      onChange={(e) =>
                        setLocationData((prev) => ({
                          ...prev,
                          is_default: e.target.checked,
                        }))
                      }
                      className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                    />
                    <span className="ml-2 text-sm text-gray-600">
                      Definir como local padrão
                    </span>
                  </label>
                </div>
              </div>

              <div className="flex justify-end space-x-3 mt-6 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={closeLocationModal}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  {locationModalMode === "create"
                    ? "Criar Local"
                    : "Salvar Alterações"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && locationToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>

            <p className="mb-6">
              Tem certeza que deseja excluir o local{" "}
              <strong>{locationToDelete.name}</strong>? Esta ação não pode ser
              desfeita.
            </p>

            <div className="flex justify-end space-x-3">
              <button
                onClick={cancelDeleteLocation}
                className="btn btn-secondary flex items-center"
              >
                <X className="h-4 w-4 mr-2" />
                Cancelar
              </button>
              <button
                onClick={deleteLocation}
                className="btn bg-red-600 text-white hover:bg-red-700 flex items-center"
              >
                <Check className="h-4 w-4 mr-2" />
                Confirmar
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Signature Upload Modal */}
      <UploadSignatureModal
        isOpen={showSignatureModal}
        onClose={() => setShowSignatureModal(false)}
        onSuccess={handleSignatureSuccess}
        currentSignatureUrl={signatureUrl}
      />
    </div>
  );
};

export default ProfessionalProfilePage;
