import type React from "react";
import { useState, useEffect } from "react";
import { useAuth } from "../../contexts/AuthContext";
import MedicalRecordPreviewModal from "../../components/MedicalRecordPreviewModal";
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
  Download,
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
    patient_type: "private" as "convenio" | "private",
    client_cpf: "",
    patient_name: "",
    patient_cpf: "",
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

  // Client search state (for convenio patients)
  const [clientSearchResult, setClientSearchResult] = useState<any>(null);
  const [dependents, setDependents] = useState<any[]>([]);
  const [selectedDependentId, setSelectedDependentId] = useState<number | null>(
    null
  );
  const [isSearching, setIsSearching] = useState(false);

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
      patient_type: "private",
      client_cpf: "",
      patient_name: "",
      patient_cpf: "",
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
    setClientSearchResult(null);
    setDependents([]);
    setSelectedDependentId(null);
    setIsModalOpen(true);
  };

  const openEditModal = (record: MedicalRecord) => {
    setModalMode("edit");

    const matchingPatient = patients.find(
      (p) => p.name === record.patient_name || p.cpf === record.patient_cpf
    );

    setFormData({
      patient_type: "private", // Default to private for editing
      client_cpf: "",
      patient_name: record.patient_name || "",
      patient_cpf: record.patient_cpf || "",
      private_patient_id: matchingPatient ? matchingPatient.id.toString() : "",
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
    setClientSearchResult(null);
    setDependents([]);
    setSelectedDependentId(null);
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

  const searchClientByCpf = async () => {
    if (!formData.client_cpf) return;

    try {
      setIsSearching(true);
      setError("");

      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();
      const cleanCpf = formData.client_cpf.replace(/\D/g, "");

      // First, try to find a dependent
      const dependentResponse = await fetch(
        `${apiUrl}/api/dependents/search?cpf=${cleanCpf}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (dependentResponse.ok) {
        const dependentData = await dependentResponse.json();

        if (dependentData.status !== "active") {
          setError("Este dependente não possui assinatura ativa.");
          return;
        }

        setClientSearchResult({
          id: dependentData.user_id,
          name: dependentData.client_name,
          subscription_status: "active",
        });
        setSelectedDependentId(dependentData.id);
        setDependents([]);

        // Set patient data for the form
        setFormData((prev) => ({
          ...prev,
          patient_name: dependentData.name,
          patient_cpf: dependentData.cpf,
        }));
        return;
      }

      // If not found as dependent, try as client
      const clientResponse = await fetch(
        `${apiUrl}/api/clients/lookup?cpf=${cleanCpf}`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (!clientResponse.ok) {
        if (clientResponse.status === 404) {
          setError("Cliente ou dependente não encontrado.");
        } else {
          setError("Erro ao buscar cliente.");
        }
        return;
      }

      const clientData = await clientResponse.json();

      if (clientData.subscription_status !== "active") {
        setError("Este cliente não possui assinatura ativa.");
        return;
      }

      setClientSearchResult(clientData);
      setSelectedDependentId(null);

      // Set patient data for the form
      setFormData((prev) => ({
        ...prev,
        patient_name: clientData.name,
        patient_cpf: clientData.cpf,
      }));

      // Fetch dependents
      const dependentsResponse = await fetch(
        `${apiUrl}/api/dependents?client_id=${clientData.id}&status=active`,
        {
          headers: { Authorization: `Bearer ${token}` },
        }
      );

      if (dependentsResponse.ok) {
        const dependentsData = await dependentsResponse.json();
        setDependents(dependentsData);
      }
    } catch (error) {
      setError("Erro ao buscar paciente.");
    } finally {
      setIsSearching(false);
    }
  };

  const formatCpf = (value: string) => {
    if (!value) return "";
    const numericValue = value.replace(/\D/g, "");
    return numericValue.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, "$1.$2.$3-$4");
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    // Validate patient selection
    if (formData.patient_type === "private" && !formData.private_patient_id) {
      setError("Selecione um paciente particular");
      return;
    }

    if (formData.patient_type === "convenio" && !clientSearchResult) {
      setError("Busque e selecione um cliente ou dependente do convênio");
      return;
    }

    try {
      const token = localStorage.getItem("token");
      const apiUrl = getApiUrl();

      // Prepare patient data for the medical record
      let patientName, patientCpf;

      if (formData.patient_type === "private") {
        const patient = patients.find(
          (p) => p.id.toString() === formData.private_patient_id
        );
        if (!patient) {
          setError("Paciente particular não encontrado");
          return;
        }
        patientName = patient.name;
        patientCpf = patient.cpf || "";
      } else {
        // Convenio patient
        if (selectedDependentId) {
          const dependent = dependents.find(
            (d) => d.id === selectedDependentId
          );
          patientName = dependent ? dependent.name : clientSearchResult.name;
          patientCpf = dependent ? dependent.cpf : formData.client_cpf;
        } else {
          patientName = clientSearchResult.name;
          patientCpf = formData.client_cpf;
        }
      }

      // Add patient info to form data
      const submitData = {
        ...formData,
        patient_type: formData.patient_type,
        patient_name: patientName,
        patient_cpf: patientCpf,
      };

      console.log("🔄 Medical record submit data:", submitData);
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
        body: JSON.stringify(submitData),
      });

      if (!response.ok) {
        const errorData = await response.json();
        console.error("❌ Medical record error:", errorData);
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

  // Função de impressão direta para prontuários
  const printMedicalRecordDirect = (record: MedicalRecord) => {
    try {
      console.log("🔄 Starting direct medical record print");

      // Gerar HTML do prontuário
      const vitalSigns = record.vital_signs || {};
      const hasVitalSigns = Object.values(vitalSigns).some(
        (value) => value && value.toString().trim()
      );

      let vitalSignsHTML = "";
      if (hasVitalSigns) {
        const vitalSignItems = [
          { label: "Pressão Arterial", value: vitalSigns.blood_pressure },
          { label: "Freq. Cardíaca", value: vitalSigns.heart_rate },
          { label: "Temperatura", value: vitalSigns.temperature },
          { label: "Freq. Respiratória", value: vitalSigns.respiratory_rate },
          { label: "Sat. O₂", value: vitalSigns.oxygen_saturation },
          { label: "Peso", value: vitalSigns.weight },
          { label: "Altura", value: vitalSigns.height },
        ].filter((item) => item.value && item.value.toString().trim());

        if (vitalSignItems.length > 0) {
          vitalSignsHTML = `
            <div style="margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #ffffff;">
              <h3 style="margin: 0 0 10px 0; color: #c11c22; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 5px; font-weight: bold;">Sinais Vitais</h3>
              <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 10px; margin: 15px 0;">
                ${vitalSignItems
                  .map(
                    (item) => `
                  <div style="text-align: center; padding: 10px; background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 4px;">
                    <div style="font-size: 11px; color: #666666; margin-bottom: 5px;">${item.label}</div>
                    <div style="font-weight: bold; color: #c11c22;">${item.value}</div>
                  </div>
                `
                  )
                  .join("")}
              </div>
            </div>
          `;
        }
      }

      const medicalSections = [
        { title: "Queixa Principal", content: record.chief_complaint },
        {
          title: "História da Doença Atual",
          content: record.history_present_illness,
        },
        {
          title: "História Médica Pregressa",
          content: record.past_medical_history,
        },
        { title: "Medicamentos em Uso", content: record.medications },
        { title: "Alergias", content: record.allergies },
        { title: "Exame Físico", content: record.physical_examination },
        { title: "Diagnóstico", content: record.diagnosis },
        { title: "Plano de Tratamento", content: record.treatment_plan },
        { title: "Observações Gerais", content: record.notes },
      ].filter((section) => section.content && section.content.trim());

      const medicalSectionsHTML = medicalSections
        .map(
          (section) => `
        <div style="margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; page-break-inside: avoid; background: #ffffff;">
          <h3 style="margin: 0 0 10px 0; color: #c11c22; font-size: 16px; border-bottom: 1px solid #eee; padding-bottom: 5px; font-weight: bold;">${section.title}</h3>
          <p style="color: #000000; margin: 10px 0; text-align: justify;">${section.content}</p>
        </div>
      `
        )
        .join("");

      const htmlContent = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prontuário Médico - ${record.patient_name}</title>
    <style>
        @page { size: A4; margin: 15mm; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Times New Roman', serif !important;
            font-size: 14px !important;
            line-height: 1.6 !important;
            color: #000000 !important;
            background: #ffffff !important;
            padding: 20px !important;
            margin: 0 !important;
            -webkit-print-color-adjust: exact !important;
            print-color-adjust: exact !important;
        }
        .header {
            text-align: center;
            margin-bottom: 40px;
            border-bottom: 2px solid #333;
            padding-bottom: 20px;
        }
        .logo {
            font-size: 24px !important;
            font-weight: bold !important;
            color: #333 !important;
            margin-bottom: 10px;
        }
        .title {
            font-size: 20px !important;
            font-weight: bold !important;
            text-transform: uppercase;
            margin: 30px 0 !important;
            text-align: center;
            color: #000000 !important;
        }
        .patient-info {
            background: #f9f9f9 !important;
            padding: 15px !important;
            border-left: 4px solid #333 !important;
            margin: 20px 0 !important;
            border-radius: 4px;
        }
        .signature {
            margin-top: 60px !important;
            text-align: center;
        }
        .signature-line {
            border-top: 1px solid #000000 !important;
            width: 300px;
            margin: 40px auto 10px !important;
        }
        .footer {
            margin-top: 40px !important;
            text-align: center;
            font-size: 12px !important;
            color: #666666 !important;
            border-top: 1px solid #dddddd !important;
            padding-top: 20px !important;
        }
        * { color: #000000 !important; }
        h1, h2, h3, h4, h5, h6 { color: #333 !important; }
        strong { font-weight: bold !important; color: #000000 !important; }
        @media print {
            body { margin: 0 !important; padding: 20px !important; background: #ffffff !important; }
            * { color: #000000 !important; -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
        }
    </style>
</head>
<body>

    <div class="title">Prontuário Médico</div>

    <div class="patient-info">
        <strong>Paciente:</strong> ${record.patient_name}<br>
        <strong>Data do Atendimento:</strong> ${new Date(
          record.created_at
        ).toLocaleDateString("pt-BR")}<br>
        <strong>Data de Emissão:</strong> ${new Date().toLocaleDateString(
          "pt-BR"
        )}
    </div>

    ${vitalSignsHTML}

    ${medicalSectionsHTML}

    ${
      medicalSections.length === 0
        ? `
    <div style="margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; background: #ffffff;">
        <p style="color: #000000; margin: 10px 0; text-align: justify;"><em>Prontuário médico sem informações clínicas detalhadas registradas.</em></p>
    </div>
    `
        : ""
    }

    <div class="signature">
        <div class="signature-line"></div>
        <div>
            <strong>${professionalData.name}</strong><br>
            ${professionalData.specialty}<br>
            ${professionalData.crm ? `Registro: ${professionalData.crm}` : ""}
        </div>
    </div>


    <script>
        window.onload = function() {
            setTimeout(function() {
                window.print();
                setTimeout(function() {
                    window.close();
                }, 1000);
            }, 500);
        };
    </script>
</body>
</html>`;

      // Criar nova janela
      const printWindow = window.open("", "_blank", "width=800,height=600");

      if (!printWindow) {
        throw new Error("Popup foi bloqueado. Permita popups para imprimir.");
      }

      // Escrever e fechar documento
      printWindow.document.write(htmlContent);
      printWindow.document.close();

      setSuccess("Janela de impressão aberta! Use Ctrl+P se necessário.");
    } catch (error) {
      console.error("Error printing medical record:", error);
      setError(
        error instanceof Error ? error.message : "Erro ao imprimir prontuário"
      );
    }
  };
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString("pt-BR", {
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
                          onClick={() => printMedicalRecordDirect(record)}
                          className="text-purple-600 hover:text-purple-900"
                          title="Imprimir Direto"
                        >
                          <Download className="h-4 w-4" />
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
                {/* Patient Type Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Tipo de Paciente *
                  </label>
                  <select
                    name="patient_type"
                    value={formData.patient_type}
                    onChange={(e) => {
                      setFormData((prev) => ({
                        ...prev,
                        patient_type: e.target.value as "convenio" | "private",
                        client_cpf: "",
                        private_patient_id: "",
                      }));
                      setClientSearchResult(null);
                      setDependents([]);
                      setSelectedDependentId(null);
                    }}
                    className="input"
                    required
                  >
                    <option value="private">Paciente Particular</option>
                    <option value="convenio">Cliente do Convênio</option>
                  </select>
                </div>

                {/* Convenio Patient Search */}
                {formData.patient_type === "convenio" && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Buscar por CPF *
                    </label>
                    <div className="flex space-x-2">
                      <input
                        type="text"
                        value={formatCpf(formData.client_cpf)}
                        onChange={(e) =>
                          setFormData((prev) => ({
                            ...prev,
                            client_cpf: e.target.value.replace(/\D/g, ""),
                          }))
                        }
                        className="input flex-1"
                        placeholder="000.000.000-00"
                      />
                      <button
                        type="button"
                        onClick={searchClientByCpf}
                        className="btn btn-secondary"
                        disabled={isSearching || !formData.client_cpf}
                      >
                        {isSearching ? "Buscando..." : "Buscar"}
                      </button>
                    </div>

                    {/* Found Client */}
                    {clientSearchResult && (
                      <div className="mt-3 p-3 bg-green-50 rounded-lg border border-green-200">
                        <div className="flex items-center mb-2">
                          <User className="h-4 w-4 text-green-600 mr-2" />
                          <span className="font-medium text-green-800">
                            Cliente: {clientSearchResult.name}
                          </span>
                        </div>

                        {/* Dependents Selection */}
                        {dependents.length > 0 && (
                          <div>
                            <label className="block text-sm font-medium text-gray-700 mb-1">
                              Dependente (opcional)
                            </label>
                            <select
                              value={selectedDependentId || ""}
                              onChange={(e) => {
                                const depId = e.target.value
                                  ? Number(e.target.value)
                                  : null;
                                setSelectedDependentId(depId);

                                // Update patient data based on selection
                                if (depId) {
                                  const dependent = dependents.find(
                                    (d) => d.id === depId
                                  );
                                  if (dependent) {
                                    setFormData((prev) => ({
                                      ...prev,
                                      patient_name: dependent.name,
                                      patient_cpf: dependent.cpf,
                                    }));
                                  }
                                } else {
                                  setFormData((prev) => ({
                                    ...prev,
                                    patient_name: clientSearchResult.name,
                                    patient_cpf: formData.client_cpf,
                                  }));
                                }
                              }}
                              className="input"
                            >
                              <option value="">
                                Prontuário para o titular
                              </option>
                              {dependents.map((dependent) => (
                                <option key={dependent.id} value={dependent.id}>
                                  {dependent.name}
                                </option>
                              ))}
                            </select>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}

                {/* Private Patient Selection */}
                {formData.patient_type === "private" && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Paciente Particular *
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
                )}

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

      {/* Preview Modal */}
      {showPreviewModal && recordToPreview && (
        <MedicalRecordPreviewModal
          record={recordToPreview}
          professionalData={professionalData}
          onClose={closePreviewModal}
        />
      )}
    </div>
  );
};

export default MedicalRecordsPage;
