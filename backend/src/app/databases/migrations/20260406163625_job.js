/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.createTable('job', function(table){
        table.uuid('id').primary();
        table.string('name').notNullable();
        table.text('description').notNullable();
        table.uuid('recruiter_id')
            .unsigned()
            .notNullable()
            .references('id')
            .inTable('recruiter');
        table.uuid('company_id')
            .unsigned()
            .notNullable()
            .references('id')
            .inTable('company')
        table.datetime('created_by')
    })
  
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
    return knex.schema.dropTable('job');
  
};
