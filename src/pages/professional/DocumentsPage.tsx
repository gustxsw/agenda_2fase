import React, { useState, useEffect } from 'react';
import { FileImage, FileText, Plus, Search, Calendar, X, Check, User, AlertCircle, Eye, Download } from 'lucide-react';

type DocumentType = 
  | 'certificate' 
  | 'prescription' 
  | 'consent_form' 
  | 'exam_request' 
  | 'declaration' 
  | 'lgpd' 
  | 'other';

type Document = {
  id: number;
  title: string;
  document_type: DocumentType;
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
  const [documents, setDocuments] = useState<Document[]>([]);
  const [patients, setPatients] = useState<PrivatePatient[]>([]);
  const [filteredDocuments, setFilteredDocuments] = useState<Document[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<DocumentType | ''>('');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [isCreating, setIsCreating] = useState(false);
  
  // Form state
  const [formData, setFormData] = useState({
    document_type: 'certificate' as DocumentType,
    patient_id: '',
    title: '',
    patientName: '',
    patientCpf: '',
    description: '',
    cid: '',
    days: '',
    procedure: '',
    risks: '',
    prescription: '',
    content: '',
    professionalName: '',
    professionalSpecialty: '',
    crm: ''
  });

  const documentTypes = [
    { value: 'certificate', label: 'Atestado Médico', icon: '📋' },
    { value: 'prescription', label: 'Receituário', icon: '💊' },
    { value: 'consent_form', label: 'Termo de Consentimento', icon: '✍️' },
    { value: 'exam_request', label: 'Solicitação de Exames', icon: '🔬' },
    { value: 'declaration', label: 'Declaração', icon: '📄' },
    { value: 'lgpd', label: 'Termo LGPD', icon: '🔒' },
    { value: 'other', label: 'Outros', icon: '📁' }
  ];

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
    console.log('🔄 DocumentsPage mounted, fetching data...');
    fetchData();
  }, []);

  // Filter documents when search term or type changes
  useEffect(() => {
    console.log('🔄 Filtering documents...', { searchTerm, selectedType, documentsCount: documents.length });
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

    console.log('✅ Filtered documents:', filtered.length);
    setFilteredDocuments(filtered);
  }, [documents, searchTerm, selectedType]);

  const fetchData = async () => {
    try {
      console.log('🔄 Starting fetchData...');
      setIsLoading(true);
      setError('');
      
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      console.log('🔄 Fetching from API:', apiUrl);

      // Fetch documents
      try {
        console.log('🔄 Fetching documents...');
        const documentsResponse = await fetch(`${apiUrl}/api/medical-documents`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        console.log('📡 Documents response status:', documentsResponse.status);

        if (documentsResponse.ok) {
          const documentsData = await documentsResponse.json();
          console.log('✅ Documents loaded:', documentsData.length);
          setDocuments(documentsData);
        } else {
          console.warn('⚠️ Documents not available:', documentsResponse.status);
          setDocuments([]);
        }
      } catch (docError) {
        console.error('❌ Error fetching documents:', docError);
        setDocuments([]);
      }

      // Fetch private patients
      try {
        console.log('🔄 Fetching private patients...');
        const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
          headers: { 'Authorization': `Bearer ${token}` }
        });

        console.log('📡 Patients response status:', patientsResponse.status);

        if (patientsResponse.ok) {
          const patientsData = await patientsResponse.json();
          console.log('✅ Patients loaded:', patientsData.length);
          setPatients(Array.isArray(patientsData) ? patientsData : []);
        } else {
          console.warn('⚠️ Patients not available:', patientsResponse.status);
          setPatients([]);
        }
      } catch (patError) {
        console.error('❌ Error fetching patients:', patError);
        setPatients([]);
      }

    } catch (error) {
      console.error('❌ Error in fetchData:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
      console.log('✅ fetchData completed');
    }
  };

  const getDocumentTypeInfo = (type: DocumentType) => {
    return documentTypes.find(dt => dt.value === type) || documentTypes[documentTypes.length - 1];
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>) => {
    const { name, value } = e.target;
    console.log('🔄 Input change:', { name, value });
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handlePatientSelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const patientId = e.target.value;
    console.log('🔄 Patient selected:', patientId);
    
    const patient = patients.find(p => p.id.toString() === patientId);
    console.log('🔄 Found patient:', patient);
    
    setFormData(prev => ({
      ...prev,
      patient_id: patientId,
      patientName: patient?.name || '',
      patientCpf: patient?.cpf || ''
    }));
  };

  const openCreateModal = () => {
    console.log('🔄 Opening create modal...');
    setFormData({
      document_type: 'certificate',
      patient_id: '',
      title: '',
      patientName: '',
      patientCpf: '',
      description: '',
      cid: '',
      days: '',
      procedure: '',
      risks: '',
      prescription: '',
      content: '',
      professionalName: '',
      professionalSpecialty: '',
      crm: ''
    });
    setError('');
    setSuccess('');
    setShowCreateModal(true);
  };

  const closeModal = () => {
    console.log('🔄 Closing modal...');
    setShowCreateModal(false);
    setError('');
    setSuccess('');
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    console.log('🔄 Submitting form with data:', formData);
    setIsCreating(true);
    setError('');
    setSuccess('');

    try {
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      console.log('🔄 Creating document via API...');

      const response = await fetch(`${apiUrl}/api/medical-documents`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          title: formData.title,
          document_type: formData.document_type,
          private_patient_id: formData.patient_id ? parseInt(formData.patient_id) : null,
          template_data: formData
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
      
      const { title, documentUrl } = result;

      // Clean filename
      const fileName = title.replace(/[^a-zA-Z0-9\s]/g, '').replace(/\s+/g, '_');
      
      // Create download link that opens in new tab for mobile compatibility
      const link = document.createElement('a');
      link.href = documentUrl;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      
      // For desktop browsers, try to force download
      if (window.navigator.userAgent.indexOf('Mobile') === -1) {
        link.download = `${fileName}.html`;
      }
      
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      setSuccess('Documento aberto em nova aba. Use Ctrl+S (ou Cmd+S no Mac) para salvar ou imprimir.');
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

  const renderFormFields = () => {
    console.log('🔄 Rendering form fields for type:', formData.document_type);
    
    switch (formData.document_type) {
      case 'certificate':
        return (
          <>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Descrição do Atestado *
              </label>
              <textarea
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                className="input min-h-[100px]"
                placeholder="Descreva o motivo do atestado..."
                required
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
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
                placeholder="Descreva o procedimento..."
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
                placeholder="Descreva os riscos e benefícios..."
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

      default:
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
    }
  };

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
      const token = localStorage.getItem('token');
      const apiUrl = getApiUrl();

      // Fetch documents
      const documentsResponse = await fetch(`${apiUrl}/api/medical-documents`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (documentsResponse.ok) {
        const documentsData = await documentsResponse.json();
        setDocuments(documentsData);
      }

      // Fetch patients
      const patientsResponse = await fetch(`${apiUrl}/api/private-patients`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (patientsResponse.ok) {
        const patientsData = await patientsResponse.json();
        setPatients(patientsData);
      }
    } catch (error) {
      console.error('Error fetching data:', error);
      setError('Não foi possível carregar os dados');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Documentos Médicos</h1>
          <p className="text-gray-600">Gere e gerencie documentos médicos</p>
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
          onChange={(e) => setSelectedType(e.target.value as DocumentType | '')}
          className="input"
        >
          <option value="">Todos os tipos</option>
          {documentTypes.map((type) => (
            <option key={type.value} value={type.value}>
              {type.icon} {type.label}
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

      {/* Create document modal */}
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
                        {type.icon} {type.label}
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