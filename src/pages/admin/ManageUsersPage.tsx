"use client";

import type React from "react";
import { useState, useEffect } from "react";
import {
  UserPlus,
  Edit,
  Trash2,
  User,
  Search,
  Filter,
  Eye,
  EyeOff,
  X,
  Check,
  AlertCircle,
  Users,
  Briefcase,
  Shield,
} from "lucide-react";

type UserData = {
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
  roles: string[];
  subscription_status: string;
  subscription_expiry: string;
  created_at: string;
  updated_at: string;
  photo_url: string;
  category_name: string;
  percentage: number;
  crm: string;
  professional_type: string;
};

const ManageUsersPage: React.FC = () => {
  const [users, setUsers] = useState<UserData[]>([]);
  const [filteredUsers, setFilteredUsers] = useState<UserData[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<"create" | "edit">("create");
  const [selectedUser, setSelectedUser] = useState<UserData | null>(null);

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
    roles: [] as string[],
    password: "",
    subscription_status: "pending",
    subscription_expiry: "",
    category_name: "",
    professional_percentage: 50,
    crm: "",
  });

  // Password visibility
  const [showPassword, setShowPassword] = useState(false);

  // Delete confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [userToDelete, setUserToDelete] = useState<UserData | null>(null);

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
    fetchUsers();
  }, []);

  useEffect(() => {
    let filtered = users;

    // Filter by search term
    if (searchTerm) {
      filtered = filtered.filter(
        (user) =>
          user.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
          user.cpf.includes(searchTerm.replace(/\D/g, "")) ||
          user.email?.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Filter by role
    if (roleFilter) {
      filtered = filtered.filter(
        (user) => user.roles && user.roles.includes(roleFilter)
      );
    }

    // Filter by subscription status
    if (statusFilter) {
      filtered = filtered.filter(
        (user) => user.subscription_status === statusFilter
      );
    }

    setFilteredUsers(filtered);
  }, [users, searchTerm, roleFilter, statusFilter]);

  const fetchUsers = async () => {
    try {
      setIsLoading(true);
      setError("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      console.log("🔄 Fetching users from:", `${apiUrl}/api/users`);

      const response = await fetch(`${apiUrl}/api/users`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      console.log("📡 Users response status:", response.status);

      if (!response.ok) {
        const errorText = await response.text();
        console.error("❌ Users response error:", errorText);
        throw new Error(`Falha ao carregar usuários: ${response.status}`);
      }

      const data = await response.json();
      console.log("✅ Users loaded:", data.length);

      // Parse roles for each user
      const usersWithParsedRoles = data.map((user: any) => ({
        ...user,
        roles:
          typeof user.roles === "string"
            ? JSON.parse(user.roles)
            : user.roles || [],
      }));

      setUsers(usersWithParsedRoles);
    } catch (error) {
      console.error("Error fetching users:", error);
      setError(
        error instanceof Error
          ? error.message
          : "Não foi possível carregar os usuários"
      );
      setUsers([]);
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
      roles: [],
      password: "",
      subscription_status: "pending",
      subscription_expiry: "",
      category_name: "",
      percentage: 50,
      crm: "",
    });
    setSelectedUser(null);
    setIsModalOpen(true);
  };

  const openEditModal = (user: UserData) => {
    setModalMode("edit");

    // Format birth_date for input field (YYYY-MM-DD)
    let formattedBirthDate = "";
    if (user.birth_date) {
      try {
        const date = new Date(user.birth_date);
        if (!isNaN(date.getTime())) {
          formattedBirthDate = date.toISOString().split("T")[0];
        }
      } catch (error) {
        console.warn("Error formatting birth date:", error);
      }
    }

    // Format subscription_expiry for input field (YYYY-MM-DD)
    let formattedExpiryDate = "";
    if (user.subscription_expiry) {
      try {
        const date = new Date(user.subscription_expiry);
        if (!isNaN(date.getTime())) {
          formattedExpiryDate = date.toISOString().split("T")[0];
        }
      } catch (error) {
        console.warn("Error formatting expiry date:", error);
      }
    }

    setFormData({
      name: user.name || "",
      cpf: user.cpf || "",
      email: user.email || "",
      phone: user.phone || "",
      birth_date: formattedBirthDate,
      address: user.address || "",
      address_number: user.address_number || "",
      address_complement: user.address_complement || "",
      neighborhood: user.neighborhood || "",
      city: user.city || "",
      state: user.state || "",
      roles: user.roles || [],
      password: "",
      subscription_status: user.subscription_status || "pending",
      subscription_expiry: formattedExpiryDate,
      category_name: user.category_name || "",
      percentage: user.percentage || 50,
      crm: user.crm || "",
      professional_type: user.professional_type || "convenio",
    });
    setSelectedUser(user);
    setIsModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setError("");
    setSuccess("");
    setShowPassword(false);
  };

  const handleInputChange = (
    e: React.ChangeEvent<
      HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement
    >
  ) => {
    const { name, value, type } = e.target;

    if (name === "roles") {
      // Handle multiple role selection
      const target = e.target as HTMLSelectElement;
      const selectedRoles = Array.from(
        target.selectedOptions,
        (option) => option.value
      );
      setFormData((prev) => ({ ...prev, roles: selectedRoles }));
    } else if (type === "checkbox") {
      const target = e.target as HTMLInputElement;
      const role = target.value;
      setFormData((prev) => ({
        ...prev,
        roles: target.checked
          ? [...prev.roles, role]
          : prev.roles.filter((r) => r !== role),
      }));
    } else {
      setFormData((prev) => ({ ...prev, [name]: value }));
    }
  };

  const formatCpf = (value: string) => {
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 11);
    setFormData((prev) => ({ ...prev, cpf: limitedValue }));
  };

  const formatPhone = (value: string) => {
    const numericValue = value.replace(/\D/g, "");
    const limitedValue = numericValue.slice(0, 11);
    setFormData((prev) => ({ ...prev, phone: limitedValue }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      // Validate form
      if (!formData.name.trim()) {
        setError("Nome é obrigatório");
        return;
      }

      if (modalMode === "create" && !formData.cpf) {
        setError("CPF é obrigatório");
        return;
      }

      if (formData.roles.length === 0) {
        setError("Pelo menos uma role deve ser selecionada");
        return;
      }

      // Validate CPF format for new users
      if (modalMode === "create") {
        const cleanCpf = formData.cpf.replace(/\D/g, "");
        if (!/^\d{11}$/.test(cleanCpf)) {
          setError("CPF deve conter 11 dígitos numéricos");
          return;
        }
      }

      // Validate professional percentage
      if (formData.roles.includes("professional")) {
        if (formData.percentage < 0 || formData.percentage > 100) {
          setError("Porcentagem do profissional deve estar entre 0 e 100");
          return;
        }
      }

      const url =
        modalMode === "create"
          ? `${apiUrl}/api/users`
          : `${apiUrl}/api/users/${selectedUser?.id}`;

      const method = modalMode === "create" ? "POST" : "PUT";

      console.log("🔄 Submitting user data:", { method, url, formData });

      const response = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      });

      console.log("📡 User submission response status:", response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ User submission error:", errorData);
        throw new Error(errorData.message || "Erro ao salvar usuário");
      }

      const responseData = await response.json();
      console.log("✅ User saved successfully:", responseData);

      setSuccess(
        modalMode === "create"
          ? "Usuário criado com sucesso!"
          : "Usuário atualizado com sucesso!"
      );

      // Show temporary password if generated
      if (modalMode === "create" && responseData.user?.temporaryPassword) {
        setSuccess(
          `Usuário criado com sucesso! Senha temporária: ${responseData.user.temporaryPassword}`
        );
      }

      await fetchUsers();

      setTimeout(() => {
        closeModal();
      }, 3000);
    } catch (error) {
      console.error("Error saving user:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao salvar usuário"
      );
    }
  };

  const confirmDelete = (user: UserData) => {
    setUserToDelete(user);
    setShowDeleteConfirm(true);
  };

  const cancelDelete = () => {
    setUserToDelete(null);
    setShowDeleteConfirm(false);
  };

  const deleteUser = async () => {
    if (!userToDelete) return;

    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      console.log("🔄 Deleting user:", userToDelete.id);

      const response = await fetch(`${apiUrl}/api/users/${userToDelete.id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });

      console.log("📡 Delete user response status:", response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ Delete user error:", errorData);
        throw new Error(errorData.message || "Erro ao excluir usuário");
      }

      console.log("✅ User deleted successfully");
      await fetchUsers();
      setSuccess("Usuário excluído com sucesso!");
    } catch (error) {
      console.error("Error deleting user:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao excluir usuário"
      );
    } finally {
      setUserToDelete(null);
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

  const formatDate = (dateString: string) => {
    // Convert from UTC (database) to Brazil local time for display
    const manageUsersUtcDate = new Date(dateString);
    const manageUsersLocalDate = new Date(
      manageUsersUtcDate.getTime() - 3 * 60 * 60 * 1000
    );
    return manageUsersLocalDate.toLocaleDateString("pt-BR");
  };

  const getRoleDisplay = (roles: string[]) => {
    if (!roles || roles.length === 0) return "Sem role";

    return roles.map((role) => {
      switch (role) {
        case "client":
          return {
            text: "Cliente",
            color: "bg-green-100 text-green-800",
            icon: <Users className="h-3 w-3" />,
          };
        case "professional":
          return {
            text: "Profissional",
            color: "bg-blue-100 text-blue-800",
            icon: <Briefcase className="h-3 w-3" />,
          };
        case "admin":
          return {
            text: "Admin",
            color: "bg-red-100 text-red-800",
            icon: <Shield className="h-3 w-3" />,
          };
        default:
          return {
            text: role,
            color: "bg-gray-100 text-gray-800",
            icon: <User className="h-3 w-3" />,
          };
      }
    });
  };

  const getStatusDisplay = (status: string) => {
    switch (status) {
      case "active":
        return { text: "Ativo", className: "bg-green-100 text-green-800" };
      case "pending":
        return { text: "Pendente", className: "bg-yellow-100 text-yellow-800" };
      case "expired":
        return { text: "Vencido", className: "bg-red-100 text-red-800" };
      default:
        return { text: status, className: "bg-gray-100 text-gray-800" };
    }
  };

  const resetFilters = () => {
    setSearchTerm("");
    setRoleFilter("");
    setStatusFilter("");
  };

  // Statistics
  const totalUsers = users.length;
  const clientsCount = users.filter((u) => u.roles?.includes("client")).length;
  const professionalsCount = users.filter((u) =>
    u.roles?.includes("professional")
  ).length;
  const adminsCount = users.filter((u) => u.roles?.includes("admin")).length;
  const activeSubscriptions = users.filter(
    (u) => u.subscription_status === "active"
  ).length;

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            Gerenciar Usuários
          </h1>
          <p className="text-gray-600">
            Adicione, edite ou remova usuários do sistema
          </p>
        </div>

        <button
          onClick={openCreateModal}
          className="btn btn-primary flex items-center"
        >
          <UserPlus className="h-5 w-5 mr-2" />
          Novo Usuário
        </button>
      </div>

      {/* Statistics Cards */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-900">{totalUsers}</div>
            <div className="text-sm text-gray-600">Total</div>
          </div>
        </div>
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">
              {clientsCount}
            </div>
            <div className="text-sm text-gray-600">Clientes</div>
          </div>
        </div>
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">
              {professionalsCount}
            </div>
            <div className="text-sm text-gray-600">Profissionais</div>
          </div>
        </div>
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-red-600">{adminsCount}</div>
            <div className="text-sm text-gray-600">Admins</div>
          </div>
        </div>
        <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-4">
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600">
              {activeSubscriptions}
            </div>
            <div className="text-sm text-gray-600">Ativos</div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100 p-6 mb-6">
        <div className="flex items-center mb-4">
          <Filter className="h-5 w-5 text-red-600 mr-2" />
          <h2 className="text-lg font-semibold">Filtros</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Buscar por nome, CPF ou email..."
              className="w-full pl-12 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
            />
          </div>

          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="input"
          >
            <option value="">Todas as roles</option>
            <option value="client">Clientes</option>
            <option value="professional">Profissionais</option>
            <option value="admin">Administradores</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="input"
          >
            <option value="">Todos os status</option>
            <option value="active">Ativo</option>
            <option value="pending">Pendente</option>
            <option value="expired">Vencido</option>
          </select>

          <button onClick={resetFilters} className="btn btn-secondary">
            Limpar Filtros
          </button>
        </div>

        {/* Results count */}
        {(searchTerm || roleFilter || statusFilter) && (
          <div className="mt-4 pt-4 border-t border-gray-200">
            <p className="text-sm text-gray-600">
              {filteredUsers.length} usuário(s) encontrado(s)
            </p>
          </div>
        )}
      </div>

      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded-lg mb-6 flex items-center">
          <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0" />
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-50 text-green-600 p-4 rounded-lg mb-6">
          {success}
        </div>
      )}

      {/* Users Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando usuários...</p>
          </div>
        ) : filteredUsers.length === 0 ? (
          <div className="text-center py-12">
            <User className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {searchTerm || roleFilter || statusFilter
                ? "Nenhum usuário encontrado"
                : "Nenhum usuário cadastrado"}
            </h3>
            <p className="text-gray-600 mb-4">
              {searchTerm || roleFilter || statusFilter
                ? "Tente ajustar os filtros de busca."
                : "Comece adicionando o primeiro usuário do sistema."}
            </p>
            {!searchTerm && !roleFilter && !statusFilter && (
              <button
                onClick={openCreateModal}
                className="btn btn-primary inline-flex items-center"
              >
                <UserPlus className="h-5 w-5 mr-2" />
                Adicionar Primeiro Usuário
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Usuário
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Contato
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Roles
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Categoria/CRM
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
                {filteredUsers.map((user) => {
                  const roleDisplays = getRoleDisplay(user.roles);
                  const statusInfo = getStatusDisplay(user.subscription_status);

                  return (
                    <tr key={user.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="flex-shrink-0 h-10 w-10">
                            {user.photo_url ? (
                              <img
                                src={user.photo_url || "/placeholder.svg"}
                                alt={user.name}
                                className="h-10 w-10 rounded-full object-cover"
                              />
                            ) : (
                              <div className="h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                                <User className="h-5 w-5 text-red-600" />
                              </div>
                            )}
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">
                              {user.name}
                            </div>
                            <div className="text-sm text-gray-500">
                              CPF: {formatCpfDisplay(user.cpf)}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-900">
                          {user.email && (
                            <div className="mb-1">{user.email}</div>
                          )}
                          {user.phone && (
                            <div className="text-gray-500">
                              {formatPhoneDisplay(user.phone)}
                            </div>
                          )}
                          {!user.email && !user.phone && (
                            <span className="text-gray-400">Não informado</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex flex-wrap gap-1">
                          {roleDisplays.map((roleInfo, index) => (
                            <span
                              key={index}
                              className={`px-2 py-1 text-xs font-medium rounded-full flex items-center ${roleInfo.color}`}
                            >
                              {roleInfo.icon}
                              <span className="ml-1">{roleInfo.text}</span>
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span
                          className={`px-2 py-1 text-xs font-medium rounded-full ${statusInfo.className}`}
                        >
                          {statusInfo.text}
                        </span>
                        {user.subscription_expiry &&
                          user.subscription_status === "active" && (
                            <div className="text-xs text-gray-500 mt-1">
                              Expira: {formatDate(user.subscription_expiry)}
                            </div>
                          )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm text-gray-900">
                          {user.category_name && (
                            <div className="mb-1">{user.category_name}</div>
                          )}
                          {user.crm && (
                            <div className="text-gray-500 text-xs">
                              Registro: {user.crm}
                            </div>
                          )}
                          {user.percentage &&
                            user.roles?.includes("professional") &&
                            user.professional_type === "convenio" && (
                              <div className="text-blue-600 text-xs">
                                {user.percentage}%
                              </div>
                            )}
                          {user.roles?.includes("professional") &&
                            user.professional_type === "agenda_only" && (
                              <div className="text-purple-600 text-xs">
                                Apenas Agenda
                              </div>
                            )}
                          {!user.category_name && !user.crm && (
                            <span className="text-gray-400 text-sm">-</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                        {formatDate(user.created_at)}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end space-x-2">
                          <button
                            onClick={() => openEditModal(user)}
                            className="text-blue-600 hover:text-blue-900"
                            title="Editar"
                          >
                            <Edit className="h-4 w-4" />
                          </button>
                          <button
                            onClick={() => confirmDelete(user)}
                            className="text-red-600 hover:text-red-900"
                            title="Excluir"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
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

      {/* User form modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">
                {modalMode === "create" ? "Novo Usuário" : "Editar Usuário"}
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
              <div className="space-y-6">
                {/* Basic Information */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Informações Básicas
                  </h3>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
                        CPF *
                      </label>
                      <input
                        type="text"
                        value={
                          formData.cpf ? formatCpfDisplay(formData.cpf) : ""
                        }
                        onChange={(e) => formatCpf(e.target.value)}
                        className="input"
                        placeholder="000.000.000-00"
                        disabled={modalMode === "edit"}
                        required={modalMode === "create"}
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Email
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
                        Telefone
                      </label>
                      <input
                        type="text"
                        value={
                          formData.phone
                            ? formatPhoneDisplay(formData.phone)
                            : ""
                        }
                        onChange={(e) => formatPhone(e.target.value)}
                        className="input"
                        placeholder="(00) 00000-0000"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Data de Nascimento
                      </label>
                      <input
                        type="date"
                        name="birth_date"
                        value={formData.birth_date}
                        onChange={handleInputChange}
                        className="input"
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Senha{" "}
                        {modalMode === "create"
                          ? "(deixe vazio para gerar automática)"
                          : "(deixe vazio para manter atual)"}
                      </label>
                      <div className="relative">
                        <input
                          type={showPassword ? "text" : "password"}
                          name="password"
                          value={formData.password}
                          onChange={handleInputChange}
                          className="input pr-10"
                          minLength={6}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                        >
                          {showPassword ? (
                            <EyeOff className="h-5 w-5" />
                          ) : (
                            <Eye className="h-5 w-5" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Roles */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Permissões de Acesso *
                  </h3>

                  <div className="space-y-3">
                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        value="client"
                        checked={formData.roles.includes("client")}
                        onChange={handleInputChange}
                        className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                      />
                      <span className="ml-3 flex items-center">
                        <Users className="h-4 w-4 text-green-600 mr-2" />
                        <span className="font-medium">Cliente</span>
                        <span className="ml-2 text-sm text-gray-500">
                          - Acesso ao painel de cliente
                        </span>
                      </span>
                    </label>

                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        value="professional"
                        checked={formData.roles.includes("professional")}
                        onChange={handleInputChange}
                        className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                      />
                      <span className="ml-3 flex items-center">
                        <Briefcase className="h-4 w-4 text-blue-600 mr-2" />
                        <span className="font-medium">Profissional</span>
                        <span className="ml-2 text-sm text-gray-500">
                          - Acesso ao painel profissional
                        </span>
                      </span>
                    </label>

                    <label className="flex items-center">
                      <input
                        type="checkbox"
                        value="admin"
                        checked={formData.roles.includes("admin")}
                        onChange={handleInputChange}
                        className="rounded border-gray-300 text-red-600 shadow-sm focus:border-red-300 focus:ring focus:ring-red-200 focus:ring-opacity-50"
                      />
                      <span className="ml-3 flex items-center">
                        <Shield className="h-4 w-4 text-red-600 mr-2" />
                        <span className="font-medium">Administrador</span>
                        <span className="ml-2 text-sm text-gray-500">
                          - Acesso total ao sistema
                        </span>
                      </span>
                    </label>
                  </div>
                </div>

                {/* Professional Information */}
                {formData.roles.includes("professional") && (
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">
                      Informações Profissionais
                    </h3>

                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Tipo de Profissional *
                        </label>
                        <select
                          name="professional_type"
                          value={formData.professional_type}
                          onChange={handleInputChange}
                          className="input"
                          required
                        >
                          <option value="convenio">
                            Profissional do Convênio
                          </option>
                          <option value="agenda_only">
                            Apenas Agenda (não aparece para clientes)
                          </option>
                        </select>
                        <p className="text-xs text-gray-500 mt-1">
                          {formData.professional_type === "convenio"
                            ? "Aparece na lista de profissionais para clientes e pode atender pelo convênio"
                            : "Não aparece para clientes, apenas usa o sistema de agenda para pacientes particulares"}
                        </p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Categoria/Especialidade
                          </label>
                          <input
                            type="text"
                            name="category_name"
                            value={formData.category_name}
                            onChange={handleInputChange}
                            className="input"
                            placeholder="Ex: Fisioterapeuta, Psicólogo"
                          />
                        </div>

                        {formData.professional_type === "convenio" && (
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                              Porcentagem (%)
                            </label>
                            <input
                              type="number"
                              name="percentage"
                              value={formData.percentage}
                              onChange={handleInputChange}
                              className="input"
                              min="0"
                              max="100"
                              placeholder="50"
                            />
                            <p className="text-xs text-gray-500 mt-1">
                              Porcentagem que o profissional recebe das
                              consultas
                            </p>
                          </div>
                        )}

                        <div>
                          <label className="block text-sm font-medium text-gray-700 mb-1">
                            Registro Profissional
                          </label>
                          <input
                            type="text"
                            name="crm"
                            value={formData.crm}
                            onChange={handleInputChange}
                            className="input"
                            placeholder="Ex: CREFITO 12345/GO, CRM 12345/GO"
                          />
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Client Information */}
                {formData.roles.includes("client") && (
                  <div>
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">
                      Status da Assinatura
                    </h3>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Status da Assinatura
                        </label>
                        <select
                          name="subscription_status"
                          value={formData.subscription_status}
                          onChange={handleInputChange}
                          className="input"
                        >
                          <option value="pending">Pendente</option>
                          <option value="active">Ativo</option>
                          <option value="expired">Vencido</option>
                        </select>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-1">
                          Data de Expiração
                        </label>
                        <input
                          type="date"
                          name="subscription_expiry"
                          value={formData.subscription_expiry}
                          onChange={handleInputChange}
                          className="input"
                        />
                        <p className="text-xs text-gray-500 mt-1">
                          Deixe vazio para definir automaticamente (1 ano) ao
                          ativar
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Address Information */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Endereço (Opcional)
                  </h3>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="md:col-span-2">
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
                    ? "Criar Usuário"
                    : "Salvar Alterações"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && userToDelete && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4 flex items-center">
              <AlertCircle className="h-6 w-6 text-red-600 mr-2" />
              Confirmar Exclusão
            </h2>

            <p className="mb-6">
              Tem certeza que deseja excluir o usuário{" "}
              <strong>{userToDelete.name}</strong>? Esta ação não pode ser
              desfeita e todos os dados relacionados serão perdidos.
            </p>

            <div className="bg-yellow-50 p-3 rounded-lg mb-6">
              <p className="text-yellow-700 text-sm">
                <strong>Atenção:</strong> Esta ação irá excluir permanentemente:
              </p>
              <ul className="text-yellow-700 text-sm mt-2 list-disc list-inside">
                <li>Dados pessoais do usuário</li>
                <li>Histórico de consultas</li>
                <li>Dependentes (se for cliente)</li>
                <li>Agendamentos</li>
                <li>Documentos médicos</li>
              </ul>
            </div>

            <div className="flex justify-end space-x-3">
              <button
                onClick={cancelDelete}
                className="btn btn-secondary flex items-center"
              >
                <X className="h-4 w-4 mr-2" />
                Cancelar
              </button>
              <button
                onClick={deleteUser}
                className="btn bg-red-600 text-white hover:bg-red-700 flex items-center"
              >
                <Check className="h-4 w-4 mr-2" />
                Confirmar Exclusão
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ManageUsersPage;
