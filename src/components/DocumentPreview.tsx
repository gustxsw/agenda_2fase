"use client";

import type React from "react";
import { useState, useEffect } from "react";
import { useAuth } from "../contexts/AuthContext";
import SimplePDFGenerator from "./SimplePDFGenerator";
import {
  Stethoscope,
  Plus,
  Search,
  User,
  Calendar,
  Edit,
  Trash2,
  Eye,
  X,
  Check,
  Printer,
} from "lucide-react";

type MedicalRecord = {
  id: number;
  patient_name: string;
  chief_complaint: string;
  history_present_illness: string;
  past_medical_history: string;
  medications: string;
  allergies: string;
  physical_examination: string;
  diagnosis: string;
  treatment_plan: string;
  notes: string;
  vital_signs: any;
  created_at: string;
  updated_at: string;
};

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
};

const MedicalRecordsPage: React.FC = () => {
  const { user } = useAuth();
  const [records, setRecords] = useState<MedicalRecord[]>([]);
  const [patients, setPatients] = useState<PrivatePatient[]>([]);
  const [filteredRecords, setFilteredRecords] = useState<MedicalRecord[]>([]);
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedPatient, setSelectedPatient] = useState<string>("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  // Modal state
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const [modalMode, setModalMode] = useState<"create" | "edit">("create");
  const [selectedRecord, setSelectedRecord] = useState<MedicalRecord | null>(
    null
  );

  // Form state
  const [formData, setFormData] = useState({
    private_patient_id: "",
    chief_complaint: "",
    history_present_illness: "",
    past_medical_history: "",
    medications: "",
    allergies: "",
    physical_examination: "",
    diagnosis: "",
    treatment_plan: "",
    notes: "",
    vital_signs: {
      blood_pressure: "",
      heart_rate: "",
      temperature: "",
      respiratory_rate: "",
      oxygen_saturation: "",
      weight: "",
      height: "",
    },
  });

  // Delete confirmation state
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [recordToDelete, setRecordToDelete] = useState<MedicalRecord | null>(
    null
  );

  // Preview state
  const [showPreviewModal, setShowPreviewModal] = useState(false);
  const [recordToPreview, setRecordToPreview] = useState<MedicalRecord | null>(
    null
  );
  const [professionalData, setProfessionalData] = useState({
    name: "",
    specialty: "",
    crm: "",
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
    fetchData();
  }, []);

  useEffect(() => {
    let filtered = records;

    if (searchTerm) {
      filtered = filtered.filter(
        (record) =>
          record.patient_name
            .toLowerCase()
            .includes(searchTerm.toLowerCase()) ||
          record.chief_complaint
            .toLowerCase()
            .includes(searchTerm.toLowerCase()) ||
          record.diagnosis.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (selectedPatient) {
      // This would need to be implemented based on patient ID
      // For now, we'll filter by patient name
      filtered = filtered.filter(
        (record) =>
          record.patient_name ===
          patients.find((p) => p.id.toString() === selectedPatient)?.name
      );
    }

    setFilteredRecords(filtered);
  }, [searchTerm, selectedPatient, records, patients]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      // Fetch professional data
      const userResponse = await fetch(`${apiUrl}/api/users/${user?.id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (userResponse.ok) {
        const userData = await userResponse.json();
        setProfessionalData({
          name: userData.name || user?.name || "Profissional",
          specialty: userData.category_name || "",
          crm: userData.crm || "",
        });
      }

      // Fetch medical records
      const recordsResponse = await fetch(`${apiUrl}/api/medical-records`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (recordsResponse.ok) {
        const recordsData = await recordsResponse.json();
        setRecords(recordsData);
      }

      // Fetch patients
      const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (patientsResponse.ok) {
        const patientsData = await patientsResponse.json();
        setPatients(patientsData);
      }
    } catch (error) {
      console.error("Error fetching data:", error);
      setError("Não foi possível carregar os dados");
    } finally {
      setIsLoading(false);
    }
  };

  const openCreateModal = () => {
    setModalMode("create");
    setFormData({
      private_patient_id: "",
      chief_complaint: "",
      history_present_illness: "",
      past_medical_history: "",
      medications: "",
      allergies: "",
      physical_examination: "",
      diagnosis: "",
      treatment_plan: "",
      notes: "",
      vital_signs: {
        blood_pressure: "",
        heart_rate: "",
        temperature: "",
        respiratory_rate: "",
        oxygen_saturation: "",
        weight: "",
        height: "",
      },
    });
    setSelectedRecord(null);
    setIsModalOpen(true);
  };

  const openEditModal = (record: MedicalRecord) => {
    setModalMode("edit");
    setFormData({
      private_patient_id: "", // Would need to be set based on the record
      chief_complaint: record.chief_complaint || "",
      history_present_illness: record.history_present_illness || "",
      past_medical_history: record.past_medical_history || "",
      medications: record.medications || "",
      allergies: record.allergies || "",
      physical_examination: record.physical_examination || "",
      diagnosis: record.diagnosis || "",
      treatment_plan: record.treatment_plan || "",
      notes: record.notes || "",
      vital_signs: record.vital_signs || {
        blood_pressure: "",
        heart_rate: "",
        temperature: "",
        respiratory_rate: "",
        oxygen_saturation: "",
        weight: "",
        height: "",
      },
    });
    setSelectedRecord(record);
    setIsModalOpen(true);
  };

  const openViewModal = (record: MedicalRecord) => {
    setSelectedRecord(record);
    setIsViewModalOpen(true);
  };

  const closeModal = () => {
    setIsModalOpen(false);
    setIsViewModalOpen(false);
    setError("");
    setSuccess("");
  };

  const handleInputChange = (
    e: React.ChangeEvent<
      HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
    >
  ) => {
    const { name, value } = e.target;

    if (name.startsWith("vital_signs.")) {
      const vitalSign = name.split(".")[1];
      setFormData((prev) => ({
        ...prev,
        vital_signs: {
          ...prev.vital_signs,
          [vitalSign]: value,
        },
      }));
    } else {
      setFormData((prev) => ({ ...prev, [name]: value }));
    }
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
          ? `${apiUrl}/api/medical-records`
          : `${apiUrl}/api/medical-records/${selectedRecord?.id}`;

      const method = modalMode === "create" ? "POST" : "PUT";

      const response = await fetch(url, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao salvar prontuário");
      }

      setSuccess(
        modalMode === "create"
          ? "Prontuário criado com sucesso!"
          : "Prontuário atualizado com sucesso!"
      );
      await fetchData();

      setTimeout(() => {
        closeModal();
      }, 1500);
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Erro ao salvar prontuário"
      );
    }
  };

  const confirmDelete = (record: MedicalRecord) => {
    setRecordToDelete(record);
    setShowDeleteConfirm(true);
  };

  const cancelDelete = () => {
    setRecordToDelete(null);
    setShowDeleteConfirm(false);
  };

  const deleteRecord = async () => {
    if (!recordToDelete) return;

    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      const response = await fetch(
        `${apiUrl}/api/medical-records/${recordToDelete.id}`,
        {
          method: "DELETE",
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || "Erro ao excluir prontuário");
      }

      await fetchData();
      setSuccess("Prontuário excluído com sucesso!");
    } catch (error) {
      setError(
        error instanceof Error ? error.message : "Erro ao excluir prontuário"
      );
    } finally {
      setRecordToDelete(null);
      setShowDeleteConfirm(false);
    }
  };

  const openPreviewModal = (record: MedicalRecord) => {
    setRecordToPreview(record);
    setShowPreviewModal(true);
  };

  const closePreviewModal = () => {
    setShowPreviewModal(false);
    setRecordToPreview(null);
  };

  const formatDate = (dateString: string) => {
    // Convert from UTC (database) to Brazil local time for display
    const utcDate = new Date(dateString);
    const docPreviewUtcDate = new Date(dateString);
    const docPreviewLocalDate = new Date(
      docPreviewUtcDate.getTime() - 3 * 60 * 60 * 1000
    );
    return docPreviewLocalDate.toLocaleDateString("pt-BR", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">
            Prontuários Médicos
          </h1>
          <p className="text-gray-600">
            Gerencie os prontuários dos seus pacientes
          </p>
        </div>

        <button
          onClick={openCreateModal}
          className="btn btn-primary flex items-center"
        >
          <Plus className="h-5 w-5 mr-2" />
          Novo Prontuário
        </button>
      </div>

      {/* Filters */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Buscar por paciente, queixa ou diagnóstico..."
            className="w-full pl-12 pr-4 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
          />
        </div>

        <select
          value={selectedPatient}
          onChange={(e) => setSelectedPatient(e.target.value)}
          className="input"
        >
          <option value="">Todos os pacientes</option>
          {patients.map((patient) => (
            <option key={patient.id} value={patient.id}>
              {patient.name}
            </option>
          ))}
        </select>
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
            <p className="text-gray-600">Carregando prontuários...</p>
          </div>
        ) : filteredRecords.length === 0 ? (
          <div className="text-center py-12">
            <Stethoscope className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {searchTerm || selectedPatient
                ? "Nenhum prontuário encontrado"
                : "Nenhum prontuário cadastrado"}
            </h3>
            <p className="text-gray-600 mb-4">
              {searchTerm || selectedPatient
                ? "Tente ajustar os filtros de busca."
                : "Comece criando o primeiro prontuário médico."}
            </p>
            {!searchTerm && !selectedPatient && (
              <button
                onClick={openCreateModal}
                className="btn btn-primary inline-flex items-center"
              >
                <Plus className="h-5 w-5 mr-2" />
                Criar Primeiro Prontuário
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
                    Queixa Principal
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Diagnóstico
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Data
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ações
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredRecords.map((record) => (
                  <tr key={record.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <div className="flex-shrink-0 h-10 w-10">
                          <div className="h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                            <User className="h-5 w-5 text-red-600" />
                          </div>
                        </div>
                        <div className="ml-4">
                          <div className="text-sm font-medium text-gray-900">
                            {record.patient_name}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm text-gray-900">
                        {record.chief_complaint || "Não informado"}
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm text-gray-900">
                        {record.diagnosis || "Não informado"}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center text-sm text-gray-500">
                        <Calendar className="h-3 w-3 mr-1" />
                        {formatDate(record.created_at)}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex items-center justify-end space-x-2">
                        <button
                          onClick={() => openViewModal(record)}
                          className="text-gray-600 hover:text-gray-900"
                          title="Visualizar"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => openPreviewModal(record)}
                          className="text-green-600 hover:text-green-900"
                          title="Gerar Documento"
                        >
                          <Printer className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => openEditModal(record)}
                          className="text-blue-600 hover:text-blue-900"
                          title="Editar"
                        >
                          <Edit className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => confirmDelete(record)}
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

      {/* Medical record form modal */}
      {isModalOpen && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <h2 className="text-xl font-bold">
                {modalMode === "create"
                  ? "Novo Prontuário"
                  : "Editar Prontuário"}
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
                {/* Patient Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Paciente *
                  </label>
                  <select
                    name="private_patient_id"
                    value={formData.private_patient_id}
                    onChange={handleInputChange}
                    className="input"
                    required
                  >
                    <option value="">Selecione um paciente</option>
                    {patients.map((patient) => (
                      <option key={patient.id} value={patient.id}>
                        {patient.name}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Vital Signs */}
                <div>
                  <h3 className="text-lg font-semibold text-gray-900 mb-4">
                    Sinais Vitais
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Pressão Arterial
                      </label>
                      <input
                        type="text"
                        name="vital_signs.blood_pressure"
                        value={formData.vital_signs.blood_pressure}
                        onChange={handleInputChange}
                        className="input"
                        placeholder="120/80"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Frequência Cardíaca
                      </label>
                      <input
                        type="text"
                        name="vital_signs.heart_rate"
                        value={formData.vital_signs.heart_rate}
                        onChange={handleInputChange}
                        className="input"
                        placeholder="72 bpm"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Temperatura
                      </label>
                      <input
                        type="text"
                        name="vital_signs.temperature"
                        value={formData.vital_signs.temperature}
                        onChange={handleInputChange}
                        className="input"
                        placeholder="36.5°C"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 mb-1">
                        Freq. Respiratória
                      </label>
                      <input
                        type="text"
                        name="vital_signs.respiratory_rate"
                        value={formData.vital_signs.respiratory_rate}
                        onChange={handleInputChange}
                        className="input"
                        placeholder="16 rpm"
                      />
                    </div>
                  </div>
                </div>

                {/* Medical Information */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Queixa Principal
                    </label>
                    <textarea
                      name="chief_complaint"
                      value={formData.chief_complaint}
                      onChange={handleInputChange}
                      className="input min-h-[100px]"
                      rows={4}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      História da Doença Atual
                    </label>
                    <textarea
                      name="history_present_illness"
                      value={formData.history_present_illness}
                      onChange={handleInputChange}
                      className="input min-h-[100px]"
                      rows={4}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      História Médica Pregressa
                    </label>
                    <textarea
                      name="past_medical_history"
                      value={formData.past_medical_history}
                      onChange={handleInputChange}
                      className="input min-h-[100px]"
                      rows={4}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Medicamentos em Uso
                    </label>
                    <textarea
                      name="medications"
                      value={formData.medications}
                      onChange={handleInputChange}
                      className="input min-h-[100px]"
                      rows={4}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Alergias
                    </label>
                    <textarea
                      name="allergies"
                      value={formData.allergies}
                      onChange={handleInputChange}
                      className="input min-h-[100px]"
                      rows={4}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Exame Físico
                    </label>
                    <textarea
                      name="physical_examination"
                      value={formData.physical_examination}
                      onChange={handleInputChange}
                      className="input min-h-[100px]"
                      rows={4}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Diagnóstico
                    </label>
                    <textarea
                      name="diagnosis"
                      value={formData.diagnosis}
                      onChange={handleInputChange}
                      className="input min-h-[100px]"
                      rows={4}
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Plano de Tratamento
                    </label>
                    <textarea
                      name="treatment_plan"
                      value={formData.treatment_plan}
                      onChange={handleInputChange}
                      className="input min-h-[100px]"
                      rows={4}
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Observações Gerais
                  </label>
                  <textarea
                    name="notes"
                    value={formData.notes}
                    onChange={handleInputChange}
                    className="input min-h-[100px]"
                    rows={4}
                  />
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
                    ? "Criar Prontuário"
                    : "Salvar Alterações"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* View modal */}
      {isViewModalOpen && selectedRecord && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200 flex justify-between items-center">
              <h2 className="text-xl font-bold">Visualizar Prontuário</h2>
              <button
                onClick={closeModal}
                className="text-gray-500 hover:text-gray-700"
              >
                <X className="h-6 w-6" />
              </button>
            </div>

            <div className="p-6 space-y-6">
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="font-semibold text-gray-900 mb-2">
                  Informações do Paciente
                </h3>
                <p>
                  <strong>Nome:</strong> {selectedRecord.patient_name}
                </p>
                <p>
                  <strong>Data do Atendimento:</strong>{" "}
                  {formatDate(selectedRecord.created_at)}
                </p>
              </div>

              {selectedRecord.vital_signs && (
                <div>
                  <h3 className="font-semibold text-gray-900 mb-2">
                    Sinais Vitais
                  </h3>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                    {selectedRecord.vital_signs.blood_pressure && (
                      <div>
                        <strong>PA:</strong>{" "}
                        {selectedRecord.vital_signs.blood_pressure}
                      </div>
                    )}
                    {selectedRecord.vital_signs.heart_rate && (
                      <div>
                        <strong>FC:</strong>{" "}
                        {selectedRecord.vital_signs.heart_rate}
                      </div>
                    )}
                    {selectedRecord.vital_signs.temperature && (
                      <div>
                        <strong>Temp:</strong>{" "}
                        {selectedRecord.vital_signs.temperature}
                      </div>
                    )}
                    {selectedRecord.vital_signs.respiratory_rate && (
                      <div>
                        <strong>FR:</strong>{" "}
                        {selectedRecord.vital_signs.respiratory_rate}
                      </div>
                    )}
                  </div>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {selectedRecord.chief_complaint && (
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-2">
                      Queixa Principal
                    </h4>
                    <p className="text-gray-700">
                      {selectedRecord.chief_complaint}
                    </p>
                  </div>
                )}

                {selectedRecord.history_present_illness && (
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-2">
                      História da Doença Atual
                    </h4>
                    <p className="text-gray-700">
                      {selectedRecord.history_present_illness}
                    </p>
                  </div>
                )}

                {selectedRecord.past_medical_history && (
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-2">
                      História Médica Pregressa
                    </h4>
                    <p className="text-gray-700">
                      {selectedRecord.past_medical_history}
                    </p>
                  </div>
                )}

                {selectedRecord.medications && (
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-2">
                      Medicamentos
                    </h4>
                    <p className="text-gray-700">
                      {selectedRecord.medications}
                    </p>
                  </div>
                )}

                {selectedRecord.allergies && (
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-2">
                      Alergias
                    </h4>
                    <p className="text-gray-700">{selectedRecord.allergies}</p>
                  </div>
                )}

                {selectedRecord.physical_examination && (
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-2">
                      Exame Físico
                    </h4>
                    <p className="text-gray-700">
                      {selectedRecord.physical_examination}
                    </p>
                  </div>
                )}

                {selectedRecord.diagnosis && (
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-2">
                      Diagnóstico
                    </h4>
                    <p className="text-gray-700">{selectedRecord.diagnosis}</p>
                  </div>
                )}

                {selectedRecord.treatment_plan && (
                  <div>
                    <h4 className="font-semibold text-gray-900 mb-2">
                      Plano de Tratamento
                    </h4>
                    <p className="text-gray-700">
                      {selectedRecord.treatment_plan}
                    </p>
                  </div>
                )}
              </div>

              {selectedRecord.notes && (
                <div>
                  <h4 className="font-semibold text-gray-900 mb-2">
                    Observações
                  </h4>
                  <p className="text-gray-700">{selectedRecord.notes}</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Medical Record Preview Modal */}
      {showPreviewModal && recordToPreview && (
        <SimplePDFGenerator
          isOpen={showPreviewModal}
          onClose={closePreviewModal}
          recordData={recordToPreview}
          professionalData={professionalData}
        />
      )}

      {/* Delete confirmation modal */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-md p-6">
            <h2 className="text-xl font-bold mb-4">Confirmar Exclusão</h2>

            <p className="mb-6">
              Tem certeza que deseja excluir este prontuário? Esta ação não pode
              ser desfeita.
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
                onClick={deleteRecord}
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

export default MedicalRecordsPage;
