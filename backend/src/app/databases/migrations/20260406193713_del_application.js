/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.dropTable('application');
  
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
    return knex.schema.createTable('application', function(table) {
        table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'))
        // recria aqui as colunas antigas se quiser desfazer
    })
};
