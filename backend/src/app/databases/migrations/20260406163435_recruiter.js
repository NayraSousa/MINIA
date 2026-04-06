/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.createTable('recruiter', function(table){
        table.uuid('id').primary();
        table.uuid('user_id')
            .unsigned()
            .notNullable()
            .unique()
            .references('id')
            .inTable('user')
            .onDelete('CASCADE')
            .onUpdate('CASCADE');
        table.uuid('company_id')
            .unsigned()
            .notNullable()
            .references('id')
            .inTable('company');
        table.string('departament');
        table.string('position');
    })
  
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
    return knex.schema.dropTable('recruiter');
  
};