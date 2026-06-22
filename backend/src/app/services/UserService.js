const userRepository = require('../repository/UserRepository')
const encrypt = require('../utils/encryptPassword');
const candidateService = require('./CandidateService');
const recruiterService = require('./RecruiterService');
const companyRepository = require('../repository/CompanyRepository');

module.exports = {
    async create({ name, email, login, password, role, github_url, linkedin_url, company_id, company_name, cnpj, department, position }) {
        const passCrypted = await encrypt.encrypt(password);
        const user = await userRepository.create(name, email, login, passCrypted, role);

        if (role === "candidate"){
            await candidateService.create(user.id, linkedin_url, github_url);
        }
        else if (role === "recruiter") {
            let resolvedCompanyId = company_id;

            if (!resolvedCompanyId) {
                if (!cnpj) {
                    throw new Error('CNPJ é obrigatório para recrutador');
                }
                const normalizedCnpj = String(cnpj).replace(/\D/g, '');
                const existing = await companyRepository.listByCnpj(normalizedCnpj);
                if (existing) {
                    resolvedCompanyId = existing.id;
                } else {
                    const created = await companyRepository.create(company_name || name, normalizedCnpj);
                    resolvedCompanyId = created.id;
                }
            }

            await recruiterService.create(user.id, resolvedCompanyId, department, position);
        }

        return user;
    },

    async listAll() {
        return userRepository.listAll();
    },

    async listById(id) {
        return userRepository.listById(id);

    },

    async update(id, data) {
        return userRepository.update(id, data);
    },

    async delete(id) {
        return userRepository.delete(id);
    }
}
