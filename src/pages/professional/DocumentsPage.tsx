import React, { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import { 
  FileText, 
  Plus, 
  Search, 
  User, 
  Calendar, 
  Eye, 
  Download, 
  X, 
  Check, 
  AlertCircle,
  Printer
} from 'lucide-react';

type Document = {
  id: number;
  title: string;
  document_type: string;
  patient_name: string;
  document_url: string;
  created_at: string;
};

type PrivatePatient = {
  id: number;
  name: string;
  cpf: string;
};

const DocumentsPage: React.FC = () => {
  const { user } = useAuth();
  const [documents, setDocuments] = useState<Document[]>([]);
  const [patients, setPatients] = useState<PrivatePatient[]>([]);
  const [filteredDocuments, setFilteredDocuments] = useState<Document[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  
  // Modal state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  
  // Form state
  const [formData, setFormData] = useState({
    document_type: 'certificate',
    title: '',
    patient_id: '',
    patientName: '',
    patientCpf: '',
    professionalName: user?.name || '',
    professionalSpecialty: '',
    crm: '',
    // Certificate fields
    description: '',
    days: '',
    cid: '',
    // Prescription fields
    prescription: '',
    // Consent form fields
    procedure: '',
    risks: '',
    // Exam request fields
    content: '',
    // Declaration fields (uses content)
    // LGPD uses default content
    // Other fields
    // content is used for other types too
  });

  const getApiUrl = () => {
    if (
      window.location.hostname === "cartaoquiroferreira.com.br" ||
      window.location.hostname === "www.cartaoquiroferreira.com.br"
    ) {
      return "https://www.cartaoquiroferreira.com.br";
    }
    return "http://localhost:3001";
  };

  const documentTypes = [
    { value: 'certificate', label: 'Atestado Médico' },
    { value: 'prescription', label: 'Receituário' },
    { value: 'consent_form', label: 'Termo de Consentimento' },
    { value: 'exam_request', label: 'Solicitação de Exames' },
    { value: 'declaration', label: 'Declaração Médica' },
    { value: 'lgpd', label: 'Termo LGPD' },
    { value: 'other', label: 'Outro Documento' }
  ];

  useEffect(() => {
    fetchData();
  }, []);

  useEffect(() => {
    let filtered = documents;

    if (searchTerm) {
      filtered = filtered.filter(doc =>
        doc.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
        doc.patient_name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    if (selectedType) {
      filtered = filtered.filter(doc => doc.document_type === selectedType);
    }

    setFilteredDocuments(filtered);
  }, [documents, searchTerm, selectedType]);

  const fetchData = async () => {
    try {
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      console.log('🔄 Fetching documents data...');

      // Fetch documents
      try {
        const documentsResponse = await fetch(`${apiUrl}/api/documents`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (documentsResponse.ok) {
          const documentsData = await documentsResponse.json();
          console.log('✅ Documents loaded:', documentsData.length);
          setDocuments(documentsData);
        } else {
          console.warn('⚠️ Documents not available:', documentsResponse.status);
          setDocuments([]);
        }
      } catch (error) {
        console.error('❌ Error fetching documents:', error);
        setDocuments([]);
      }

      // Fetch patients
      try {
        const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (patientsResponse.ok) {
          const patientsData = await patientsResponse.json();
          console.log('✅ Patients loaded:', patientsData.length);
          setPatients(patientsData);
        } else {
          console.warn('⚠️ Patients not available:', patientsResponse.status);
          setPatients([]);
        }
      } catch (error) {
        console.error('❌ Error fetching patients:', error);
        setPatients([]);
      }

      // Fetch user data for professional info
      try {
        const userResponse = await fetch(`${apiUrl}/api/users/${user?.id}`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        if (userResponse.ok) {
          const userData = await userResponse.json();
          setFormData(prev => ({
            ...prev,
            professionalName: userData.name || user?.name || '',
            professionalSpecialty: userData.category_name || '',
            crm: userData.crm || ''
          }));
        }
      } catch (error) {
        console.error('❌ Error fetching user data:', error);
      }

    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };

  const openCreateModal = () => {
    console.log('🔄 Opening create modal...');
    setShowCreateModal(true);
    setError('');
    setSuccess('');
  };

  const closeModal = () => {
    console.log('🔄 Closing modal...');
    setShowCreateModal(false);
    setError('');
    setSuccess('');
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handlePatientSelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const patientId = e.target.value;
    const patient = patients.find(p => p.id.toString() === patientId);
    
    setFormData(prev => ({
      ...prev,
      patient_id: patientId,
      patientName: patient?.name || '',
      patientCpf: patient?.cpf || ''
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    console.log('🔄 Submitting document form...');

    try {
      setIsCreating(true);
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      // Prepare template data based on document type
      let templateData: any = {
        patientName: formData.patientName,
        patientCpf: formData.patientCpf,
        professionalName: formData.professionalName,
        professionalSpecialty: formData.professionalSpecialty,
        crm: formData.crm
      };

      // Add specific fields based on document type
      switch (formData.document_type) {
        case 'certificate':
          templateData = {
            ...templateData,
            description: formData.description,
            days: formData.days,
            cid: formData.cid
          };
          break;
        case 'prescription':
          templateData = {
            ...templateData,
            prescription: formData.prescription
          };
          break;
        case 'consent_form':
          templateData = {
            ...templateData,
            procedure: formData.procedure,
            description: formData.description,
            risks: formData.risks
          };
          break;
        case 'exam_request':
          templateData = {
            ...templateData,
            content: formData.content
          };
          break;
        case 'declaration':
          templateData = {
            ...templateData,
            content: formData.content
          };
          break;
        case 'lgpd':
          // LGPD uses default template
          break;
        case 'other':
          templateData = {
            ...templateData,
            title: formData.title,
            content: formData.content
          };
          break;
      }

      console.log('🔄 Template data:', templateData);

      const response = await fetch(`${apiUrl}/api/documents`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          document_type: formData.document_type,
          title: formData.title,
          private_patient_id: parseInt(formData.patient_id),
          template_data: templateData
        })
      });

      console.log('📡 Document creation response status:', response.status);

      if (!response.ok) {
        const errorData = await response.json();
        console.error('❌ Document creation error:', errorData);
        throw new Error(errorData.message || 'Erro ao criar documento');
      }

      const result = await response.json();
      console.log('✅ Document created:', result);

      setSuccess('Documento criado com sucesso!');
      await fetchData();

      setTimeout(() => {
        closeModal();
      }, 1500);
    } catch (error) {
      console.error('❌ Error creating document:', error);
      setError(error instanceof Error ? error.message : 'Erro ao criar documento');
    } finally {
      setIsCreating(false);
    }
  };

  const getDocumentTypeInfo = (type: string) => {
    const typeMap: { [key: string]: { label: string; icon: string } } = {
      certificate: { label: 'Atestado Médico', icon: '📋' },
      prescription: { label: 'Receituário', icon: '💊' },
      consent_form: { label: 'Termo de Consentimento', icon: '📝' },
      exam_request: { label: 'Solicitação de Exames', icon: '🔬' },
      declaration: { label: 'Declaração Médica', icon: '📄' },
      lgpd: { label: 'Termo LGPD', icon: '🔒' },
      other: { label: 'Outro Documento', icon: '📃' }
    };
    return typeMap[type] || { label: 'Documento', icon: '📄' };
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('pt-BR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const renderFormFields = () => {
    switch (formData.document_type) {
      case 'certificate':
        return (
          <>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Descrição do Problema *
              </label>
              <textarea
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                className="input min-h-[100px]"
                placeholder="Descreva o problema de saúde que justifica o atestado"
                required
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Dias de Afastamento *
                </label>
                <input
                  type="number"
                  name="days"
                  value={formData.days}
                  onChange={handleInputChange}
                  className="input"
                  min="1"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  CID (opcional)
                </label>
                <input
                  type="text"
                  name="cid"
                  value={formData.cid}
                  onChange={handleInputChange}
                  className="input"
                  placeholder="Ex: M54.5"
                />
              </div>
            </div>
          </>
        );

      case 'prescription':
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Prescrição Médica *
            </label>
            <textarea
              name="prescription"
              value={formData.prescription}
              onChange={handleInputChange}
              className="input min-h-[200px]"
              placeholder="Digite a prescrição médica completa..."
              required
            />
          </div>
        );

      case 'consent_form':
        return (
          <>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Procedimento *
              </label>
              <input
                type="text"
                name="procedure"
                value={formData.procedure}
                onChange={handleInputChange}
                className="input"
                placeholder="Nome do procedimento"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Descrição do Procedimento *
              </label>
              <textarea
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                className="input min-h-[100px]"
                placeholder="Descreva o procedimento em detalhes"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Riscos e Benefícios *
              </label>
              <textarea
                name="risks"
                value={formData.risks}
                onChange={handleInputChange}
                className="input min-h-[100px]"
                placeholder="Descreva os riscos e benefícios do procedimento"
                required
              />
            </div>
          </>
        );

      case 'exam_request':
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Exames Solicitados *
            </label>
            <textarea
              name="content"
              value={formData.content}
              onChange={handleInputChange}
              className="input min-h-[200px]"
              placeholder="Liste os exames solicitados..."
              required
            />
          </div>
        );

      case 'declaration':
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Conteúdo da Declaração *
            </label>
            <textarea
              name="content"
              value={formData.content}
              onChange={handleInputChange}
              className="input min-h-[200px]"
              placeholder="Digite o conteúdo da declaração médica..."
              required
            />
          </div>
        );

      case 'lgpd':
        return (
          <div className="bg-blue-50 p-4 rounded-lg">
            <p className="text-blue-800 text-sm">
              O termo LGPD será gerado automaticamente com o conteúdo padrão sobre proteção de dados pessoais.
            </p>
          </div>
        );

      case 'other':
        return (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Conteúdo do Documento *
            </label>
            <textarea
              name="content"
              value={formData.content}
              onChange={handleInputChange}
              className="input min-h-[200px]"
              placeholder="Digite o conteúdo do documento..."
              required
            />
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Documentos Médicos</h1>
          <p className="text-gray-600">Crie e gerencie documentos médicos</p>
        </div>
        
        <button
          onClick={openCreateModal}
          className="btn btn-primary flex items-center"
        >
          <Plus className="h-5 w-5 mr-2" />
          Novo Documento
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
            placeholder="Buscar por título ou paciente..."
            className="input pl-10"
          />
        </div>

        <select
          value={selectedType}
          onChange={(e) => setSelectedType(e.target.value)}
          className="input"
        >
          <option value="">Todos os tipos</option>
          {documentTypes.map((type) => (
            <option key={type.value} value={type.value}>
              {type.label}
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

      {/* Documents Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-100">
        {isLoading ? (
          <div className="text-center py-12">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto mb-4"></div>
            <p className="text-gray-600">Carregando documentos...</p>
          </div>
        ) : filteredDocuments.length === 0 ? (
          <div className="text-center py-12">
            <FileText className="h-16 w-16 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">
              {searchTerm || selectedType ? 'Nenhum documento encontrado' : 'Nenhum documento criado'}
            </h3>
            <p className="text-gray-600 mb-4">
              {searchTerm || selectedType
                ? 'Tente ajustar os filtros de busca.'
                : 'Comece criando seu primeiro documento médico.'
              }
            </p>
            {!searchTerm && !selectedType && (
              <button
                onClick={openCreateModal}
                className="btn btn-primary inline-flex items-center"
              >
                <Plus className="h-5 w-5 mr-2" />
                Criar Primeiro Documento
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Documento
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Paciente
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Tipo
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Data de Criação
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Ações
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredDocuments.map((document) => {
                  const typeInfo = getDocumentTypeInfo(document.document_type);
                  return (
                    <tr key={document.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="flex-shrink-0 h-10 w-10">
                            <div className="h-10 w-10 rounded-full bg-red-100 flex items-center justify-center">
                              <FileText className="h-5 w-5 text-red-600" />
                            </div>
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">
                              {document.title}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <User className="h-4 w-4 text-gray-400 mr-2" />
                          <span className="text-sm text-gray-900">{document.patient_name}</span>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                          {typeInfo.icon} {typeInfo.label}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center text-sm text-gray-500">
                          <Calendar className="h-3 w-3 mr-1" />
                          {formatDate(document.created_at)}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end space-x-2">
                          <a
                            href={document.document_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-600 hover:text-blue-900"
                            title="Visualizar"
                          >
                            <Eye className="h-4 w-4" />
                          </a>
                          <a
                            href={document.document_url}
                            download
                            className="text-green-600 hover:text-green-900"
                            title="Download"
                          >
                            <Download className="h-4 w-4" />
                          </a>
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

      {/* Create Document Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-xl w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-200">
              <div className="flex justify-between items-center">
                <h2 className="text-xl font-bold">Criar Novo Documento</h2>
                <button
                  onClick={closeModal}
                  className="text-gray-400 hover:text-gray-600"
                  type="button"
                >
                  <X className="h-6 w-6" />
                </button>
              </div>
            </div>

            {error && (
              <div className="mx-6 mt-4 bg-red-50 text-red-600 p-3 rounded-lg">
                <div className="flex items-center">
                  <AlertCircle className="h-5 w-5 mr-2" />
                  {error}
                </div>
              </div>
            )}

            {success && (
              <div className="mx-6 mt-4 bg-green-50 text-green-600 p-3 rounded-lg">
                <div className="flex items-center">
                  <Check className="h-5 w-5 mr-2" />
                  {success}
                </div>
              </div>
            )}

            <form onSubmit={handleSubmit} className="p-6">
              <div className="space-y-6">
                {/* Document Type */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Tipo de Documento *
                  </label>
                  <select
                    name="document_type"
                    value={formData.document_type}
                    onChange={handleInputChange}
                    className="input"
                    required
                  >
                    {documentTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                </div>

                {/* Title */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Título do Documento *
                  </label>
                  <input
                    type="text"
                    name="title"
                    value={formData.title}
                    onChange={handleInputChange}
                    className="input"
                    placeholder="Ex: Atestado Médico - João Silva"
                    required
                  />
                </div>

                {/* Patient Selection */}
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Paciente *
                  </label>
                  <select
                    value={formData.patient_id}
                    onChange={handlePatientSelect}
                    className="input"
                    required
                  >
                    <option value="">Selecione um paciente</option>
                    {patients.map((patient) => (
                      <option key={patient.id} value={patient.id}>
                        {patient.name} - CPF: {patient.cpf.replace(/(\d{3})(\d{3})(\d{3})(\d{2})/, '$1.$2.$3-$4')}
                      </option>
                    ))}
                  </select>
                  {patients.length === 0 && (
                    <p className="text-sm text-gray-500 mt-1">
                      Nenhum paciente particular cadastrado. Cadastre pacientes primeiro na seção "Pacientes Particulares".
                    </p>
                  )}
                </div>

                {/* Professional Information */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Nome do Profissional *
                    </label>
                    <input
                      type="text"
                      name="professionalName"
                      value={formData.professionalName}
                      onChange={handleInputChange}
                      className="input"
                      required
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Especialidade
                    </label>
                    <input
                      type="text"
                      name="professionalSpecialty"
                      value={formData.professionalSpecialty}
                      onChange={handleInputChange}
                      className="input"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      CRM
                    </label>
                    <input
                      type="text"
                      name="crm"
                      value={formData.crm}
                      onChange={handleInputChange}
                      className="input"
                      placeholder="Ex: 12345/GO"
                    />
                  </div>
                </div>

                {/* Dynamic form fields based on document type */}
                {renderFormFields()}
              </div>

              <div className="flex justify-end space-x-3 mt-8 pt-6 border-t border-gray-200">
                <button
                  type="button"
                  onClick={closeModal}
                  className="btn btn-secondary"
                  disabled={isCreating}
                >
                  Cancelar
                </button>
                <button 
                  type="submit" 
                  className={`btn btn-primary ${isCreating ? 'opacity-70 cursor-not-allowed' : ''}`}
                  disabled={isCreating}
                >
                  {isCreating ? 'Criando...' : 'Criar Documento'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default DocumentsPage;