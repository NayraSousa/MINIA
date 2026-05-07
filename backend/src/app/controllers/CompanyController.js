const companyService = require('../services/CompanyService');
const { update } = require('./CandidateController');

module.exports = {
    async create(request, response) {
        const { name, cnpj } = request.body;
        company = await companyService.create(name, cnpj);

        return response.status(201).json({ company });
    },

    async listAll(request, response) {
        const companies = await companyService.listAll();

        return response.status(200).json({ companies });
    },

    async listById(request, response) {
        const { id } = request.params;
        const companyFiltered = await companyService.listById(id);
        return response.status(200).json({companyFiltered});
    },

    async update(request, response){
        const { id } = request.params;
        const data = Object.fromEntries(
            Object.entries(request.body).filter(([_, v]) => v !== undefined)
        );

        const companyUpdated = await companyService.update(id, data);
        return response.status(200).json({companyUpdated});
    },

    async delete(request, response) {
        const { id } = request.params;
        const companyDeleted = await companyService.delete(id);

        return response.status(200).json({companyDeleted});
    }
}