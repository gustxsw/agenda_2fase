import type React from "react";
import { useState, useEffect } from "react";
import {
  UserPlus,
  Edit,
  Trash2,
  User,
  Search,
  Phone,
  Mail,
  MapPin,
  Calendar,
  X,
  Check,
  Filter,
  RefreshCw,
  Users,
} from "lucide-react";

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
  email: string;
  phone: string;
  birth_date: string;
  address: string;
  address_number: string;
  address_complement: string;
  neighborhood: string;
  city: string;
  state: string;
  zip_code: string;
  created_at: string;
};

const PrivatePatientsPage: React.FC = () => {
  const [patients, setPatients] = useState<PrivatePatient[]>([]);
  const [filteredPatients, setFilteredPatients] = useState<PrivatePatient[]>(
    []
  );
  const [searchTerm, setSearchTerm] = useState("");
  const [searchType, setSearchType] = useState<"name" | "cpf" | "phone">(
    "name"
  );
  const [isSearching, setIsSearching] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<"create" | "edit">("create");
  const [selectedPatient, setSelectedPatient] = useState<PrivatePatient | null>(
    null
  );

  // Form state
  const [formData, setFormData] = useState({
    name: "",
    cpf: "",
    email: "",
    phone: "",
    birth_date: "",
    address: "",
    address_number: "",
    address_complement: "",
    neighborhood: "",
    city: "",
    state: "",
    zip_code: "",
  });

  // Delete confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [patientToDelete, setPatientToDelete] = useState<PrivatePatient | null>(
    null
  );

  // Advanced search state
  const [showAdvancedSearch, setShowAdvancedSearch] = useState(false);
  const [advancedSearchData, setAdvancedSearchData] = useState({
    name: "",
    cpf: "",
    phone: "",
    email: "",
    city: "",
    state: "",
  });

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
    fetchPatients();
  }, []);

  useEffect(() => {
    filterPatients();
  }, [searchTerm, patients]);

  const filterPatients = () => {
    let filtered = patients;

    if (searchTerm.trim()) {
      const searchValue = searchTerm.toLowerCase().trim();

      filtered = filtered.filter((patient) => {
        switch (searchType) {
          case "name":
            return patient.name.toLowerCase().includes(searchValue);
          case "cpf":
            return (
              patient.cpf &&
              patient.cpf
                .replace(/\D/g, "")
                .includes(searchValue.replace(/\D/g, ""))
            );
          case "phone":
            return (
              patient.phone &&
              patient.phone
                .replace(/\D/g, "")
                .includes(searchValue.replace(/\D/g, ""))
            );
          default:
            return (
              patient.name.toLowerCase().includes(searchValue) ||
              (patient.cpf &&
                patient.cpf.includes(searchValue.replace(/\D/g, ""))) ||
              (patient.phone &&
                patient.phone.includes(searchValue.replace(/\D/g, "")))
            );
        }
      });
    }

    setFilteredPatients(filtered);
  };

  const performAdvancedSearch = () => {
    setIsSearching(true);

    let filtered = patients;

    // Apply advanced search filters
    if (advancedSearchData.name.trim()) {
      filtered = filtered.filter((patient) =>
        patient.name
          .toLowerCase()
          .includes(advancedSearchData.name.toLowerCase().trim())
      );
    }

    if (advancedSearchData.cpf.trim()) {
      const cleanCpf = advancedSearchData.cpf.replace(/\D/g, "");
      filtered = filtered.filter(
        (patient) =>
          patient.cpf && patient.cpf.replace(/\D/g, "").includes(cleanCpf)
      );
    }

    if (advancedSearchData.phone.trim()) {
      const cleanPhone = advancedSearchData.phone.replace(/\D/g, "");
      filtered = filtered.filter(
        (patient) =>
          patient.phone && patient.phone.replace(/\D/g, "").includes(cleanPhone)
      );
    }

    if (advancedSearchData.email.trim()) {
      filtered = filtered.filter(
        (patient) =>
          patient.email &&
          patient.email
            .toLowerCase()
            .includes(advancedSearchData.email.toLowerCase().trim())
      );
    }

    if (advancedSearchData.city.trim()) {
      filtered = filtered.filter(
        (patient) =>
          patient.city &&
          patient.city
            .toLowerCase()
            .includes(advancedSearchData.city.toLowerCase().trim())
      );
    }

    if (advancedSearchData.state) {
      filtered = filtered.filter(
        (patient) => patient.state === advancedSearchData.state
      );
    }

    setFilteredPatients(filtered);
    setIsSearching(false);
    setShowAdvancedSearch(false);
  };

  const clearAdvancedSearch = () => {
    setAdvancedSearchData({
      name: "",
      cpf: "",
      phone: "",
      email: "",
      city: "",
      state: "",
    });
    setFilteredPatients(patients);
    setShowAdvancedSearch(false);
  };

  const clearSimpleSearch = () => {
    setSearchTerm("");
    setFilteredPatients(patients);
  };

  const fetchPatients = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const response = await fetch(`${apiUrl}/api/private-patients`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!response.ok) {
        throw new Error("Falha ao carregar pacientes");
      }

      const data = await response.json();
      setPatients(data);
    } catch (error) {
      console.error("Error fetching patients:", error);
      setError("Não foi possível carregar os pacientes");
    } finally {
      setIsLoading(false);
    }
  };

  const openCreateModal = () => {
    setModalMode("create");
    setFormData({
      name: "",
      cpf: "",
      email: "",
      phone: "",
      birth_date: "",
      address: "",
      address_number: "",
      address_complement: "",
      neighborhood: "",
      city: "",
      state: "",
      zip_code: "",
    });
    setSelectedPatient(null);
    setIsModalOpen(true);
  };

  const openEditModal = (patient: PrivatePatient) => {
    setModalMode("edit");
    setFormData({
      name: patient.name || "",
      cpf: patient.cpf || "",
      email: patient.email || "",
      phone: patient.phone || "",
      birth_date: patient.birth_date || "",
      address: patient.address || "",
      address_number: patient.address_number || "",
      address_complement: patient.address_complement || "",
      neighborhood: patient.neighborhood || "",
      city: patient.city || "",
      state: patient.state || "",
      zip_code: patient.zip_code || "",
    });
    setSelectedPatient(patient);
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setError("");
    setSuccess("");
  };

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 11);
    setFormData((prev) => ({ ...prev, cpf: limitedValue }));
  };

  const formatPhone = (value: string) => {
    if (!value) return;
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 11);
    setFormData((prev) => ({ ...prev, phone: limitedValue }));
  };

  const formatZipCode = (value: string) => {
    if (!value) return;
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 8);
    setFormData((prev) => ({ ...prev, zip_code: limitedValue }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const url =
        modalMode === "create"
          ? `${apiUrl}/api/private-patients`
          : `${apiUrl}/api/private-patients/${selectedPatient?.id}`;

      const method = modalMode === "create" ? "POST" : "PUT";

      // Prepare data with optional CPF
      const submitData = {
        ...formData,
        cpf: (formData.cpf || "").trim() || null, // Send null if CPF is empty
        email: (formData.email || "").trim() || null,
        phone: formData.phone.replace(/\D/g, "") || null,
        birth_date: formData.birth_date || null,
        address: (formData.address || "").trim() || null,
        address_number: (formData.address_number || "").trim() || null,
        address_complement: (formData.address_complement || "").trim() || null,
        neighborhood: (formData.neighborhood || "").trim() || null,
        city: (formData.city || "").trim() || null,
        state: formData.state || null,
        zip_code: formData.zip_code.replace(/\D/g, "") || null,
      };

      const response = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(submitData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao salvar paciente");
      }

      setSuccess(
        modalMode === "create"
          ? "Paciente criado com sucesso!"
          : "Paciente atualizado com sucesso!"
      );
      await fetchPatients();

      setTimeout(() => {
        closeModal();
      }, 1500);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Erro ao salvar paciente"
      );
    }
  };

  const confirmDelete = (patient: PrivatePatient) => {
    setPatientToDelete(patient);
    setShowDeleteConfirm(true);
  };

  const cancelDelete = () => {
    setPatientToDelete(null);
    setShowDeleteConfirm(false);
  };

  const deletePatient = async () => {
    if (!patientToDelete) return;

    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const response = await fetch(
        `${apiUrl}/api/private-patients/${patientToDelete.id}`,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao excluir paciente");
      }

      await fetchPatients();
      setSuccess("Paciente excluído com sucesso!");
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Erro ao excluir paciente"
      );
    } finally {
      setPatientToDelete(null);
      setShowDeleteConfirm(false);
    }
  };

  const formatCpfDisplay = (cpf: string) => {
    if (!cpf) return "";
    return cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4");
  };

  const formatPhoneDisplay = (phone: string) => {
    if (!phone) return "";
    const cleaned = phone.replace(/\D/g, "");
    if (cleaned.length === 11) {
      return `(${cleaned.slice(0, 2)}) ${cleaned.slice(2, 7)}-${cleaned.slice(
        7
      )}`;
    } else if (cleaned.length === 10) {
      return `(${cleaned.slice(0, 2)}) ${cleaned.slice(2, 6)}-${cleaned.slice(
        6
      )}`;
    }
    return phone;
  };

  const formatZipCodeDisplay = (zipCode: string) => {
    if (!zipCode) return "";
    return zipCode.replace(/(\d{5})(\d{3})/, "$1-$2");
  };

  const formatDate = (dateString: string) => {
    if (!dateString) return "";
    // Convert from UTC (database) to Brazil local time for display
    const patientsUtcDate = new Date(dateString);
    const patientsLocalDate = new Date(
      patientsUtcDate.getTime() - 3 * 60 * 60 * 1000
    );
    return patientsLocalDate.toLocaleDateString("pt-BR");
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            Pacientes Particulares
          </h1>
          <p className="text-gray-600">Gerencie seus pacientes particulares</p>
        </div>

        <button
          onClick={openCreateModal}
          className="btn btn-primary flex items-center"
        >
          <UserPlus className="h-5 w-5 mr-2" />
          Novo Paciente
        </button>
      </div>

      {/* Search Section */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center">
            <Search className="h-5 w-5 text-red-600 mr-2" />
            <h2 className="text-lg font-semibold">Buscar Pacientes</h2>
          </div>

          <div className="flex space-x-2">
            <button
              onClick={() => setShowAdvancedSearch(!showAdvancedSearch)}
              className="btn btn-outline flex items-center"
            >
              <Filter className="h-4 w-4 mr-2" />
              Busca Avançada
            </button>

            <button
              onClick={() => {
                clearSimpleSearch();
                clearAdvancedSearch();
              }}
              className="btn btn-secondary flex items-center"
            >
              <RefreshCw className="h-4 w-4 mr-2" />
              Limpar
            </button>
          </div>
        </div>

        {/* Simple Search */}
        {!showAdvancedSearch && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Tipo de Busca
              </label>
              <select
                value={searchType}
                onChange={(e) =>
                  setSearchType(e.target.value as "name" | "cpf" | "phone")
                }
                className="input"
              >
                <option value="name">Por Nome</option>
                <option value="cpf">Por CPF</option>
                <option value="phone">Por Telefone</option>
              </select>
            </div>

            <div className="md:col-span-2">
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Termo de Busca
              </label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder={
                    searchType === "name"
                      ? "Digite o nome do paciente..."
                      : searchType === "cpf"
                      ? "Digite o CPF (apenas números)..."
                      : "Digite o telefone (apenas números)..."
                  }
                  className="w-full pl-12 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                />
              </div>
            </div>
          </div>
        )}

        {/* Advanced Search */}
        {showAdvancedSearch && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Nome
                </label>
                <input
                  type="text"
                  value={advancedSearchData.name}
                  onChange={(e) =>
                    setAdvancedSearchData((prev) => ({
                      ...prev,
                      name: e.target.value,
                    }))
                  }
                  className="input"
                  placeholder="Nome do paciente"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  CPF
                </label>
                <input
                  type="text"
                  value={advancedSearchData.cpf}
                  onChange={(e) =>
                    setAdvancedSearchData((prev) => ({
                      ...prev,
                      cpf: e.target.value.replace(/\D/g, "").slice(0, 11),
                    }))
                  }
                  className="input"
                  placeholder="00000000000"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Telefone
                </label>
                <input
                  type="text"
                  value={advancedSearchData.phone}
                  onChange={(e) =>
                    setAdvancedSearchData((prev) => ({
                      ...prev,
                      phone: e.target.value.replace(/\D/g, "").slice(0, 11),
                    }))
                  }
                  className="input"
                  placeholder="00000000000"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Email
                </label>
                <input
                  type="email"
                  value={advancedSearchData.email}
                  onChange={(e) =>
                    setAdvancedSearchData((prev) => ({
                      ...prev,
                      email: e.target.value,
                    }))
                  }
                  className="input"
                  placeholder="email@exemplo.com"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Cidade
                </label>
                <input
                  type="text"
                  value={advancedSearchData.city}
                  onChange={(e) =>
                    setAdvancedSearchData((prev) => ({
                      ...prev,
                      city: e.target.value,
                    }))
                  }
                  className="input"
                  placeholder="Nome da cidade"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Estado
                </label>
                <select
                  value={advancedSearchData.state}
                  onChange={(e) =>
                    setAdvancedSearchData((prev) => ({
                      ...prev,
                      state: e.target.value,
                    }))
                  }
                  className="input"
                >
                  <option value="">Todos os estados</option>
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
            </div>

            <div className="flex justify-end space-x-3">
              <button
                onClick={clearAdvancedSearch}
                className="btn btn-secondary flex items-center"
              >
                <X className="h-4 w-4 mr-2" />
                Limpar Filtros
              </button>
              <button
                onClick={performAdvancedSearch}
                className={`btn btn-primary flex items-center ${
                  isSearching ? "opacity-70 cursor-not-allowed" : ""
                }`}
                disabled={isSearching}
              >
                {isSearching ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    Buscando...
                  </>
                ) : (
                  <>
                    <Search className="h-4 w-4 mr-2" />
                    Buscar
                  </>
                )}
              </button>
            </div>
          </div>
        )}

        {/* Search Results Info */}
        {(searchTerm ||
          Object.values(advancedSearchData).some((val) => val.trim())) && (
          <div className="mt-4 pt-4 border-t border-gray-200">
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-600">
                {filteredPatients.length} paciente(s) encontrado(s)
                {searchTerm && ` para "${searchTerm}"`}
              </p>

              {filteredPatients.length > 0 && (
                <div className="flex items-center space-x-4 text-xs text-gray-500">
                  <div className="flex items-center">
                    <Users className="h-3 w-3 mr-1" />
                    Total: {patients.length}
                  </div>
                  <div className="flex items-center">
                    <Search className="h-3 w-3 mr-1" />
                    Filtrados: {filteredPatients.length}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
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

      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando pacientes...</p>
          </div>
        ) : filteredPatients.length === 0 ? (
          <div className="text-center py-12">
            <User className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {searchTerm
                ? "Nenhum paciente encontrado"
                : "Nenhum paciente cadastrado"}
            </h3>
            <p className="text-gray-600 mb-4">
              {searchTerm
                ? "Tente ajustar os termos de busca."
                : "Comece adicionando seu primeiro paciente particular."}
            </p>
            {!searchTerm && (
              <button
                onClick={openCreateModal}
                className="btn btn-primary inline-flex items-center"
              >
                <UserPlus className="h-5 w-5 mr-2" />
                Adicionar Primeiro Paciente
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Paciente
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Contato
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Endereço
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Data de Cadastro
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ações
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredPatients.map((patient) => (
                  <tr key={patient.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-10 w-10">
                          <div className="h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                            <User className="h-5 w-5 text-red-600" />
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">
                            {patient.name}
                          </div>
                          {patient.cpf && (
                            <div className="text-sm text-gray-500">
                              CPF: {formatCpfDisplay(patient.cpf)}
                            </div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">
                        {patient.phone && (
                          <div className="flex items-center mb-1">
                            <Phone className="h-3 w-3 text-gray-400 mr-1" />
                            {formatPhoneDisplay(patient.phone)}
                          </div>
                        )}
                        {patient.email && (
                          <div className="flex items-center">
                            <Mail className="h-3 w-3 text-gray-400 mr-1" />
                            {patient.email}
                          </div>
                        )}
                        {!patient.phone && !patient.email && (
                          <span className="text-gray-400 text-sm">
                            Não informado
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-gray-900">
                        {patient.address && (
                          <div className="flex items-start">
                            <MapPin className="h-3 w-3 text-gray-400 mr-1 mt-0.5" />
                            <div>
                              <div>
                                {patient.address}
                                {patient.address_number &&
                                  `, ${patient.address_number}`}
                              </div>
                              {patient.city && patient.state && (
                                <div className="text-xs text-gray-500">
                                  {patient.city}, {patient.state}
                                </div>
                              )}
                            </div>
                          </div>
                        )}
                        {!patient.address && (
                          <span className="text-gray-400 text-sm">
                            Não informado
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center text-sm text-gray-500">
                        <Calendar className="h-3 w-3 mr-1" />
                        {formatDate(patient.created_at)}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex items-center justify-end space-x-2">
                        <button
                          onClick={() => openEditModal(patient)}
                          className="text-blue-600 hover:text-blue-900"
                          title="Editar"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => confirmDelete(patient)}
                          className="text-red-600 hover:text-red-900"
                          title="Excluir"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Patient form modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">
                {modalMode === "create" ? "Novo Paciente" : "Editar Paciente"}
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
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Personal Information */}
                <div className="md:col-span-2">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Informações Pessoais
                  </h3>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Nome Completo *
                  </label>
                  <input
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleInputChange}
                    className="input"
                    required
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    CPF (opcional)
                  </label>
                  <input
                    type="text"
                    value={formData.cpf ? formatCpfDisplay(formData.cpf) : ""}
                    onChange={(e) => formatCpf(e.target.value)}
                    className="input"
                    placeholder="000.000.000-00"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Email (opcional)
                  </label>
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleInputChange}
                    className="input"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Telefone (opcional)
                  </label>
                  <input
                    type="text"
                    value={
                      formData.phone ? formatPhoneDisplay(formData.phone) : ""
                    }
                    onChange={(e) => formatPhone(e.target.value)}
                    className="input"
                    placeholder="(00) 00000-0000"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Data de Nascimento (opcional)
                  </label>
                  <input
                    type="date"
                    name="birth_date"
                    value={formData.birth_date}
                    onChange={handleInputChange}
                    className="input"
                  />
                </div>

                {/* Address Information */}
                <div className="md:col-span-2 mt-6">
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Endereço (opcional)
                  </h3>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    CEP
                  </label>
                  <input
                    type="text"
                    value={
                      formData.zip_code
                        ? formatZipCodeDisplay(formData.zip_code)
                        : ""
                    }
                    onChange={(e) => formatZipCode(e.target.value)}
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
                    name="address"
                    value={formData.address}
                    onChange={handleInputChange}
                    className="input"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Número
                  </label>
                  <input
                    type="text"
                    name="address_number"
                    value={formData.address_number}
                    onChange={handleInputChange}
                    className="input"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Complemento
                  </label>
                  <input
                    type="text"
                    name="address_complement"
                    value={formData.address_complement}
                    onChange={handleInputChange}
                    className="input"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Bairro
                  </label>
                  <input
                    type="text"
                    name="neighborhood"
                    value={formData.neighborhood}
                    onChange={handleInputChange}
                    className="input"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Cidade
                  </label>
                  <input
                    type="text"
                    name="city"
                    value={formData.city}
                    onChange={handleInputChange}
                    className="input"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Estado
                  </label>
                  <select
                    name="state"
                    value={formData.state}
                    onChange={handleInputChange}
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
              </div>

              <div className="flex justify-end space-x-3 mt-8 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={closeModal}
                  className="btn btn-secondary"
                >
                  Cancelar
                </button>
                <button type="submit" className="btn btn-primary">
                  {modalMode === "create"
                    ? "Criar Paciente"
                    : "Salvar Alterações"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && patientToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>

            <p className="mb-6">
              Tem certeza que deseja excluir o paciente{" "}
              <strong>{patientToDelete.name}</strong>? Esta ação não pode ser
              desfeita.
            </p>

            <div className="flex justify-end space-x-3">
              <button
                onClick={cancelDelete}
                className="btn btn-secondary flex items-center"
              >
                <X className="h-4 w-4 mr-2" />
                Cancelar
              </button>
              <button
                onClick={deletePatient}
                className="btn bg-red-600 text-white hover:bg-red-700 flex items-center"
              >
                <Check className="h-4 w-4 mr-2" />
                Confirmar
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PrivatePatientsPage;
