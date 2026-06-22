const conn = require('../databases/conn')

module.exports = {
    async create(name, cnpj){
        const [company] = await conn('company').insert(
            {
            name,
            cnpj
            }
        ).returning(['id']);
    return company;
    },

    async listAll(){
        const companies = await conn('company').select(
            'id',
            'name',
            'cnpj'
        );
        return companies;
    },

    async listById(id){
        const companyFiltered = await conn('company').select(
            'id',
            'name',
            'cnpj'
        ).where('id', id).first();
        return companyFiltered;
    },

    async listByCnpj(cnpj){
        const companyFiltered = await conn('company').select(
            'id',
            'name',
            'cnpj'
        ).where('cnpj', cnpj).first();
        return companyFiltered;
    },

    async update(id, data){
        const companyUpdated = await conn('company')
            .where({ id })
            .update(data)
            .returning(['id']);
        
        return companyUpdated;
    },

    async delete(id){
        const companyDeleted = await conn('company')
            .where({ id })
            .delete()
            .returning(['id']);

        return companyDeleted;
    }

}