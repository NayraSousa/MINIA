/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.createTable('candidate', function(table){
        table.uuid('id').primary();
        table.uuid('user_id')
            .unsigned()
            .notNullable()
            .unique()
            .references('id')
            .inTable('user')
            .onDelete('CASCADE')
            .onUpdate('CASCADE');
        table.text('curriculum');
        table.string('linkedin_url');
        table.string('github_url');            
    })
  
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
    return knex.schema.dropTable('candidate');
  
};
