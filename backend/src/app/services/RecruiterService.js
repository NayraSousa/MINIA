const CandidateRepository = require('../repository/CandidateRepository');
const recruiterRepository = require('../repository/RecruiterRepository');
const companyRepository = require('../repository/CompanyRepository');
const { listById, update } = require('./CandidateService');

module.exports = {
    async create (user_id, company_id, departament, position) {
        return recruiterRepository.create(user_id, company_id, departament, position);

    },

    async completeProfile({ user_id, company_name, cnpj, department, position }) {
        if(!cnpj){
            throw new Error('CNPJ é obrigatório para completar o perfil de recrutador');
        }

        const normalizedCnpj = String(cnpj).replace(/\D/g, '');
        let company = await companyRepository.listByCnpj(normalizedCnpj);
        if(!company){
            company = await companyRepository.create(company_name || 'Empresa', normalizedCnpj);
        }

        const existing = await recruiterRepository.listByUserId(user_id);
        if(existing && existing.length > 0){
            return existing[0];
        }

        return recruiterRepository.create(user_id, company.id, department, position);
    },

    async listAll() {
        return recruiterRepository.listAll();

    },

    async listById(id) {
        return recruiterRepository.listById(id);

    },

    async listByUserId(user_id) {
        return recruiterRepository.listByUserId(user_id);

    },

    async update(id, data) {
        return recruiterRepository.update(id, data);

    },

    async delete(id) {
        return CandidateRepository.delete(id);
        
    }
}