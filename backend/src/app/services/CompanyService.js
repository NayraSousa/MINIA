const companyService = require('../repository/CompanyRepository')

module.exports = {
    async create(name, cnpj){
        return companyService.create(name, cnpj);
    },

    async listAll(){
        return companyService.listAll();
    },

    async listById(){
        return companyService.listById();
    },

    async update(id, data){
        return companyService.update(id, data);
    },

    async delete(id){
        return companyService.delete(id);
    }
}