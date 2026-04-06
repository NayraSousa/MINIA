/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.createTable('user', function(table){
        table.uuid('id').primary();
        table.string('name').notNullable();
        table.string('email').notNullable();
        table.string('login', 50).unique().notNullable();
        table.string('password', 255).notNullable();
        table.string('role').notNullable();
        table.datetime('created_at').notNullable();
    })
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
    return knex.schema.dropTable('user')

};
