"use client";

import type React from "react";
import { AlertTriangle, X, Phone } from "lucide-react";

type ConflictInfo = {
  date: string;
  time: string;
  clientName: string;
};

type ScheduleConflictModalProps = {
  isOpen: boolean;
  onClose: () => void;
  conflicts: ConflictInfo[];
  isSingleConflict?: boolean;
};

const ScheduleConflictModal: React.FC<ScheduleConflictModalProps> = ({
  isOpen,
  onClose,
  conflicts,
  isSingleConflict = false,
}) => {
  if (!isOpen || conflicts.length === 0) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-[60] p-4">
      <div className="bg-white rounded-xl w-full max-w-2xl max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="p-6 border-b border-amber-200 bg-gradient-to-r from-amber-50 to-orange-50">
          <div className="flex justify-between items-start">
            <div className="flex items-start space-x-3">
              <div className="flex-shrink-0 w-12 h-12 bg-amber-100 rounded-full flex items-center justify-center">
                <AlertTriangle className="h-6 w-6 text-amber-600" />
              </div>
              <div>
                <h2 className="text-xl font-bold text-amber-900">
                  {isSingleConflict
                    ? "Horário Já Agendado"
                    : `${conflicts.length} Horário${
                        conflicts.length > 1 ? "s" : ""
                      } Já Agendado${conflicts.length > 1 ? "s" : ""}`}
                </h2>
                <p className="text-sm text-amber-700 mt-1">
                  {isSingleConflict
                    ? "Este horário já possui um agendamento"
                    : "Os seguintes horários já possuem agendamentos"}
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-amber-400 hover:text-amber-600 transition-colors"
            >
              <X className="h-6 w-6" />
            </button>
          </div>
        </div>

        {/* Conflicts List */}
        <div className="p-6">
          <div className="space-y-3 max-h-[400px] overflow-y-auto">
            {conflicts.map((conflict, index) => (
              <div
                key={index}
                className="bg-gradient-to-r from-amber-50 to-orange-50 border-2 border-amber-200 rounded-lg p-4 hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 space-y-2">
                    <div className="flex items-center space-x-2">
                      <div className="w-8 h-8 bg-amber-500 text-white rounded-full flex items-center justify-center font-bold text-sm">
                        {index + 1}
                      </div>
                      <h3 className="font-semibold text-amber-900 text-lg">
                        {conflict.clientName}
                      </h3>
                    </div>

                    <div className="ml-10 space-y-1">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-medium text-amber-700 bg-amber-100 px-2 py-1 rounded">
                          DATA
                        </span>
                        <span className="text-sm font-medium text-amber-900">
                          {conflict.date}
                        </span>
                      </div>

                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-medium text-amber-700 bg-amber-100 px-2 py-1 rounded">
                          HORA
                        </span>
                        <span className="text-sm font-medium text-amber-900">
                          {conflict.time}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Action Message */}
          <div className="mt-6 p-4 bg-blue-50 border-2 border-blue-200 rounded-lg">
            <div className="flex items-start space-x-3">
              <Phone className="h-5 w-5 text-blue-600 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="font-semibold text-blue-900 mb-1">
                  Próximos Passos
                </h4>
                <p className="text-sm text-blue-800">
                  Entre em contato com{" "}
                  {conflicts.length > 1 ? "os clientes" : "o cliente"} para
                  reagendar{" "}
                  {conflicts.length > 1 ? "estes horários" : "este horário"} ou
                  escolha{" "}
                  {conflicts.length > 1 ? "outros horários" : "outro horário"}{" "}
                  disponíveis na agenda.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-gray-200 bg-gray-50">
          <div className="flex justify-end">
            <button onClick={onClose} className="btn btn-primary px-6">
              Entendi
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScheduleConflictModal;
