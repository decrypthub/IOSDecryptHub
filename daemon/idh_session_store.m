#import "idh_session_store.h"
#include <sqlite3.h>
#include <string.h>

@implementation IDHSessionStore {
    sqlite3 *_database;
}

- (instancetype)initWithPath:(NSString *)path {
    self = [super init];
    if (!self) return nil;
    if (sqlite3_open_v2(path.fileSystemRepresentation, &_database,
                       SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) return nil;
    sqlite3_busy_timeout(_database, 1000);
    const char *schema =
        "PRAGMA foreign_keys=ON;"
        "CREATE TABLE IF NOT EXISTS sessions("
        "id TEXT PRIMARY KEY, created_ms INTEGER NOT NULL, bundle_id TEXT, value BLOB NOT NULL);"
        "CREATE TABLE IF NOT EXISTS summaries("
        "session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,"
        "seq INTEGER NOT NULL, value BLOB NOT NULL, PRIMARY KEY(session_id,seq));";
    if (![self execute:schema]) return nil;
    if (![self ensureBundleColumn]) return nil;
    return self;
}

// 旧库的 sessions 表没有 bundle_id 列；补列后从 value JSON 里回填
- (BOOL)ensureBundleColumn {
    sqlite3_stmt *statement = NULL;
    BOOL found = NO;
    if (sqlite3_prepare_v2(_database, "PRAGMA table_info(sessions);", -1, &statement, NULL) == SQLITE_OK) {
        while (sqlite3_step(statement) == SQLITE_ROW) {
            const char *name = (const char *)sqlite3_column_text(statement, 1);
            if (name && strcmp(name, "bundle_id") == 0) { found = YES; break; }
        }
    }
    sqlite3_finalize(statement);
    if (!found && ![self execute:"ALTER TABLE sessions ADD COLUMN bundle_id TEXT;"]) return NO;
    statement = NULL;
    NSMutableArray<NSArray *> *pending = [NSMutableArray array];
    if (sqlite3_prepare_v2(_database, "SELECT id,value FROM sessions WHERE bundle_id IS NULL;",
                           -1, &statement, NULL) != SQLITE_OK) return NO;
    while (sqlite3_step(statement) == SQLITE_ROW) {
        const char *identity = (const char *)sqlite3_column_text(statement, 0);
        NSData *data = [NSData dataWithBytes:sqlite3_column_blob(statement, 1)
                                     length:sqlite3_column_bytes(statement, 1)];
        id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        NSString *bundle = [value isKindOfClass:NSDictionary.class] ? value[@"bundleId"] : nil;
        if (identity && [bundle isKindOfClass:NSString.class])
            [pending addObject:@[[NSString stringWithUTF8String:identity], bundle]];
    }
    sqlite3_finalize(statement);
    statement = NULL;
    if (sqlite3_prepare_v2(_database, "UPDATE sessions SET bundle_id=? WHERE id=?;",
                           -1, &statement, NULL) != SQLITE_OK) return NO;
    for (NSArray *row in pending) {
        sqlite3_bind_text(statement, 1, [row[1] UTF8String], -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 2, [row[0] UTF8String], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) != SQLITE_DONE) {
            sqlite3_finalize(statement);
            return NO;
        }
        sqlite3_reset(statement);
    }
    sqlite3_finalize(statement);
    return YES;
}

- (void)dealloc {
    if (_database) sqlite3_close(_database);
}

- (BOOL)execute:(const char *)sql {
    if (sqlite3_exec(_database, sql, NULL, NULL, NULL) == SQLITE_OK) return YES;
    NSLog(@"idhjd storage: %s", sqlite3_errmsg(_database));
    return NO;
}

static BOOL bindJSON(sqlite3_stmt *statement, int index, NSDictionary *record) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:record options:0 error:NULL];
    return data.length &&
        sqlite3_bind_blob(statement, index, data.bytes, (int)data.length, SQLITE_TRANSIENT) == SQLITE_OK;
}

- (BOOL)save:(NSDictionary *)session events:(NSArray<NSDictionary *> *)events {
    if (![self execute:"BEGIN IMMEDIATE"]) return NO;
    sqlite3_stmt *statement = NULL;
    const char *upsert =
        "INSERT INTO sessions(id,created_ms,bundle_id,value) VALUES(?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET bundle_id=excluded.bundle_id, value=excluded.value;";
    const char *identity = [session[@"sessionId"] UTF8String];
    const char *bundle = [session[@"bundleId"] UTF8String];
    BOOL saved = sqlite3_prepare_v2(_database, upsert, -1, &statement, NULL) == SQLITE_OK &&
        sqlite3_bind_text(statement, 1, identity, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(statement, 2, [session[@"createdAtMs"] longLongValue]) == SQLITE_OK &&
        (bundle ? sqlite3_bind_text(statement, 3, bundle, -1, SQLITE_TRANSIENT)
                : sqlite3_bind_null(statement, 3)) == SQLITE_OK &&
        bindJSON(statement, 4, session) && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    statement = NULL;
    if (saved && events.count) {
        saved = sqlite3_prepare_v2(_database, "INSERT INTO summaries(session_id,seq,value) VALUES(?,?,?);",
                                   -1, &statement, NULL) == SQLITE_OK;
        for (NSDictionary *event in events) {
            if (!saved) break;
            saved = sqlite3_bind_text(statement, 1, identity, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
                sqlite3_bind_int64(statement, 2, [event[@"seq"] longLongValue]) == SQLITE_OK &&
                bindJSON(statement, 3, event) && sqlite3_step(statement) == SQLITE_DONE;
            sqlite3_reset(statement);
        }
        sqlite3_finalize(statement);
    }
    if (saved && [self execute:"COMMIT"]) return YES;
    NSLog(@"idhjd could not commit session: %s", sqlite3_errmsg(_database));
    [self execute:"ROLLBACK"];
    return NO;
}

- (NSArray<NSDictionary *> *)select:(const char *)sql session:(NSString *)sessionID
                             after:(uint64_t)cursor limit:(NSUInteger)limit {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(_database, sql, -1, &statement, NULL) != SQLITE_OK) return nil;
    if (sessionID) sqlite3_bind_text(statement, 1, sessionID.UTF8String, -1, SQLITE_TRANSIENT);
    if (limit) {
        sqlite3_bind_int64(statement, 2, (sqlite3_int64)cursor);
        sqlite3_bind_int64(statement, 3, (sqlite3_int64)limit);
    }
    NSMutableArray *rows = [NSMutableArray array];
    int result;
    while ((result = sqlite3_step(statement)) == SQLITE_ROW) {
        NSData *data = [NSData dataWithBytes:sqlite3_column_blob(statement, 0)
                                     length:sqlite3_column_bytes(statement, 0)];
        id value = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
        if (![value isKindOfClass:NSDictionary.class]) {
            sqlite3_finalize(statement);
            return nil;
        }
        [rows addObject:value];
    }
    sqlite3_finalize(statement);
    return result == SQLITE_DONE ? rows : nil;
}

- (NSArray<NSDictionary *> *)sessions {
    return [self select:"SELECT value FROM sessions ORDER BY rowid DESC;"
                session:nil after:0 limit:0];
}

- (NSDictionary *)session:(NSString *)sessionID {
    return [[self select:"SELECT value FROM sessions WHERE id=?;"
                 session:sessionID after:0 limit:0] firstObject];
}

- (NSArray<NSDictionary *> *)eventsForSession:(NSString *)sessionID after:(uint64_t)cursor limit:(NSUInteger)limit {
    return [self select:"SELECT value FROM summaries WHERE session_id=? AND seq>? ORDER BY seq LIMIT ?;"
                session:sessionID after:cursor limit:limit];
}

// 按 App 合并的连续时间线：跨该 bundleId 全部会话，按 summaries.rowid（入库顺序≈时间序）升序。
// 每条事件附加 appSeq = rowid，作为应用级连续序号与翻页游标。
- (NSArray<NSDictionary *> *)eventsForBundle:(NSString *)bundle after:(uint64_t)cursor limit:(NSUInteger)limit {
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(_database,
            "SELECT summaries.rowid,summaries.value FROM summaries "
            "JOIN sessions ON summaries.session_id = sessions.id "
            "WHERE sessions.bundle_id = ? AND summaries.rowid > ? ORDER BY summaries.rowid LIMIT ?;",
            -1, &statement, NULL) != SQLITE_OK) return nil;
    sqlite3_bind_text(statement, 1, bundle.UTF8String, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(statement, 2, (sqlite3_int64)cursor);
    sqlite3_bind_int64(statement, 3, (sqlite3_int64)limit);
    NSMutableArray *rows = [NSMutableArray array];
    int result;
    while ((result = sqlite3_step(statement)) == SQLITE_ROW) {
        NSData *data = [NSData dataWithBytes:sqlite3_column_blob(statement, 1)
                                     length:sqlite3_column_bytes(statement, 1)];
        id value = [NSJSONSerialization JSONObjectWithData:data
                                                   options:NSJSONReadingMutableContainers error:NULL];
        if (![value isKindOfClass:NSMutableDictionary.class]) {
            sqlite3_finalize(statement);
            return nil;
        }
        ((NSMutableDictionary *)value)[@"appSeq"] = @(sqlite3_column_int64(statement, 0));
        [rows addObject:value];
    }
    sqlite3_finalize(statement);
    return result == SQLITE_DONE ? rows : nil;
}

- (BOOL)prune {
    return [self execute:"DELETE FROM sessions WHERE id IN "
                         "(SELECT id FROM sessions ORDER BY rowid DESC LIMIT -1 OFFSET 20);"];
}
@end
