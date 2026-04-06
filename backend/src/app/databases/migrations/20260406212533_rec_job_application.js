/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function(knex) {
    return knex.schema.createTable('job_application', function(table){
        table.uuid('id').primary().defaultTo(knex.raw('gen_random_uuid()'));
        table.uuid('candidate_id')
            .unsigned()
            .notNullable()
            .references('id')
            .inTable('candidate');
        table.uuid('job_id')
            .unsigned()
            .notNullable()
            .references('id')
            .inTable('job');
        table.string('status').notNullable();
        table.double('ai_score');
        table.dateTime('created_at');
        
    })
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function(knex) {
    return knex.schema.dropTable('job_application');
};
