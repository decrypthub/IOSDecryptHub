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
    sqlite3_busy_timeout(_database, 2000);
    const char *schema =
        "PRAGMA journal_mode=WAL;"
        "CREATE TABLE IF NOT EXISTS app_events("
        "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
        "bundle_id TEXT NOT NULL,"
        "category INTEGER NOT NULL,"
        "time_ms INTEGER NOT NULL,"
        "value BLOB NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_app_events_bundle_seq ON app_events(bundle_id, seq);"
        "CREATE INDEX IF NOT EXISTS idx_app_events_bundle_cat_seq ON app_events(bundle_id, category, seq);"
        "CREATE TABLE IF NOT EXISTS app_stats("
        "bundle_id TEXT PRIMARY KEY,"
        "total INTEGER NOT NULL DEFAULT 0,"
        "updated_ms INTEGER NOT NULL DEFAULT 0,"
        "last_seq INTEGER NOT NULL DEFAULT 0,"
        "by_cat TEXT NOT NULL DEFAULT '[0,0,0,0,0,0,0,0,0]');";
    if (![self execute:schema]) return nil;
    return self;
}

- (void)dealloc {
    if (_database) sqlite3_close(_database);
}

- (BOOL)execute:(const char *)sql {
    if (sqlite3_exec(_database, sql, NULL, NULL, NULL) == SQLITE_OK) return YES;
    NSLog(@"idhjd storage: %s", sqlite3_errmsg(_database));
    return NO;
}

static NSMutableArray<NSNumber *> *parseCounts(const unsigned char *text) {
    NSMutableArray<NSNumber *> *counts = [NSMutableArray arrayWithObjects:@0,@0,@0,@0,@0,@0,@0,@0,@0, nil];
    if (!text) return counts;
    NSData *data = [NSData dataWithBytes:text length:strlen((const char *)text)];
    id arr = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if ([arr isKindOfClass:NSArray.class]) {
        NSUInteger limit = MIN([arr count], 9U);
        for (NSUInteger i = 0; i < limit; i++) {
            if ([arr[i] isKindOfClass:NSNumber.class]) counts[i] = @([arr[i] longLongValue]);
        }
    }
    return counts;
}

static NSString *encodeCounts(NSArray<NSNumber *> *counts) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:counts options:0 error:NULL];
    return data ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"[0,0,0,0,0,0,0,0,0]";
}

static NSDictionary *emptySummary(NSString *bundle) {
    return @{
        @"bundleId": bundle ?: @"",
        @"count": @0,
        @"updatedAtMs": @0,
        @"lastSeq": @0,
        @"byCategory": @[@0,@0,@0,@0,@0,@0,@0,@0,@0],
    };
}

- (BOOL)appendEvents:(NSArray<NSDictionary *> *)events
           forBundle:(NSString *)bundle
           maxPerApp:(NSUInteger)maxPerApp {
    if (!bundle.length) return NO;
    if (!events.count) return YES;
    if (![self execute:"BEGIN IMMEDIATE"]) return NO;

    int64_t total = 0, updatedMs = 0, lastSeq = 0;
    NSMutableArray<NSNumber *> *byCat = parseCounts(NULL);
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(_database,
            "SELECT total,updated_ms,last_seq,by_cat FROM app_stats WHERE bundle_id=?;",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, bundle.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            total = sqlite3_column_int64(stmt, 0);
            updatedMs = sqlite3_column_int64(stmt, 1);
            lastSeq = sqlite3_column_int64(stmt, 2);
            byCat = parseCounts(sqlite3_column_text(stmt, 3));
        }
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    BOOL ok = sqlite3_prepare_v2(_database,
        "INSERT INTO app_events(bundle_id,category,time_ms,value) VALUES(?,?,?,?);",
        -1, &stmt, NULL) == SQLITE_OK;
    for (NSDictionary *event in events) {
        if (!ok) break;
        int cat = [event[@"category"] intValue];
        if (cat < 0 || cat > 8) cat = 8;
        int64_t ts = [event[@"timeMs"] longLongValue];
        NSData *blob = [NSJSONSerialization dataWithJSONObject:event options:0 error:NULL];
        ok = blob.length > 0 &&
            sqlite3_bind_text(stmt, 1, bundle.UTF8String, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_bind_int(stmt, 2, cat) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 3, ts) == SQLITE_OK &&
            sqlite3_bind_blob(stmt, 4, blob.bytes, (int)blob.length, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_reset(stmt);
        if (ok) {
            lastSeq = sqlite3_last_insert_rowid(_database);
            total++;
            if (ts > updatedMs) updatedMs = ts;
            byCat[cat] = @(MAX(0LL, [byCat[cat] longLongValue] + 1));
        }
    }
    sqlite3_finalize(stmt);
    stmt = NULL;

    if (ok && maxPerApp > 0 && total > (int64_t)maxPerApp) {
        int64_t excess = total - (int64_t)maxPerApp;
        int64_t trimThrough = 0;
        if (sqlite3_prepare_v2(_database,
                "SELECT seq,category FROM app_events WHERE bundle_id=? ORDER BY seq ASC LIMIT ?;",
                -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, bundle.UTF8String, -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, excess);
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                trimThrough = sqlite3_column_int64(stmt, 0);
                int cat = sqlite3_column_int(stmt, 1);
                if (cat < 0 || cat > 8) cat = 8;
                total = MAX(0LL, total - 1);
                byCat[cat] = @(MAX(0LL, [byCat[cat] longLongValue] - 1));
            }
        } else {
            ok = NO;
        }
        sqlite3_finalize(stmt);
        stmt = NULL;
        if (ok && trimThrough > 0) {
            ok = sqlite3_prepare_v2(_database,
                "DELETE FROM app_events WHERE bundle_id=? AND seq<=?;",
                -1, &stmt, NULL) == SQLITE_OK &&
                sqlite3_bind_text(stmt, 1, bundle.UTF8String, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
                sqlite3_bind_int64(stmt, 2, trimThrough) == SQLITE_OK &&
                sqlite3_step(stmt) == SQLITE_DONE;
            sqlite3_finalize(stmt);
            stmt = NULL;
        }
    }

    if (ok) {
        NSString *catJSON = encodeCounts(byCat);
        ok = sqlite3_prepare_v2(_database,
            "INSERT INTO app_stats(bundle_id,total,updated_ms,last_seq,by_cat) VALUES(?,?,?,?,?) "
            "ON CONFLICT(bundle_id) DO UPDATE SET total=excluded.total, updated_ms=excluded.updated_ms, "
            "last_seq=excluded.last_seq, by_cat=excluded.by_cat;",
            -1, &stmt, NULL) == SQLITE_OK &&
            sqlite3_bind_text(stmt, 1, bundle.UTF8String, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 2, total) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 3, updatedMs) == SQLITE_OK &&
            sqlite3_bind_int64(stmt, 4, lastSeq) == SQLITE_OK &&
            sqlite3_bind_text(stmt, 5, catJSON.UTF8String, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
    }

    if (ok && [self execute:"COMMIT"]) return YES;
    NSLog(@"idhjd could not commit app events: %s", sqlite3_errmsg(_database));
    [self execute:"ROLLBACK"];
    return NO;
}

- (NSArray<NSDictionary *> *)appSummaries {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(_database,
            "SELECT bundle_id,total,updated_ms,last_seq,by_cat FROM app_stats WHERE total>0 ORDER BY updated_ms DESC;",
            -1, &stmt, NULL) != SQLITE_OK) return nil;
    NSMutableArray *rows = [NSMutableArray array];
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *bid = (const char *)sqlite3_column_text(stmt, 0);
        if (!bid) continue;
        [rows addObject:@{
            @"bundleId": [NSString stringWithUTF8String:bid],
            @"count": @(sqlite3_column_int64(stmt, 1)),
            @"updatedAtMs": @(sqlite3_column_int64(stmt, 2)),
            @"lastSeq": @(sqlite3_column_int64(stmt, 3)),
            @"byCategory": parseCounts(sqlite3_column_text(stmt, 4)),
        }];
    }
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE ? rows : nil;
}

- (NSDictionary *)appSummaryForBundle:(NSString *)bundle {
    if (!bundle.length) return emptySummary(@"");
    sqlite3_stmt *stmt = NULL;
    NSDictionary *summary = nil;
    if (sqlite3_prepare_v2(_database,
            "SELECT total,updated_ms,last_seq,by_cat FROM app_stats WHERE bundle_id=?;",
            -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, bundle.UTF8String, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            summary = @{
                @"bundleId": bundle,
                @"count": @(sqlite3_column_int64(stmt, 0)),
                @"updatedAtMs": @(sqlite3_column_int64(stmt, 1)),
                @"lastSeq": @(sqlite3_column_int64(stmt, 2)),
                @"byCategory": parseCounts(sqlite3_column_text(stmt, 3)),
            };
        }
    }
    sqlite3_finalize(stmt);
    return summary ?: emptySummary(bundle);
}

- (NSDictionary *)queryEventsForBundle:(NSString *)bundle
                            categories:(NSArray<NSNumber *> *)categories
                                 after:(NSNumber *)after
                                before:(NSNumber *)before
                                 limit:(NSUInteger)limit {
    if (!bundle.length || !limit || limit > 500) return nil;
    NSMutableString *catClause = [NSMutableString string];
    if (categories.count > 0 && categories.count < 9) {
        NSMutableArray<NSString *> *nums = [NSMutableArray array];
        for (NSNumber *n in categories) {
            int c = n.intValue;
            if (c >= 0 && c <= 8) [nums addObject:[NSString stringWithFormat:@"%d", c]];
        }
        if (!nums.count) {
            NSDictionary *summary = [self appSummaryForBundle:bundle];
            return @{@"ok": @YES, @"events": @[], @"hasOlder": @NO, @"hasMore": @NO,
                     @"oldestSeq": @0, @"latestSeq": summary[@"lastSeq"], @"next": @0, @"summary": summary};
        }
        [catClause appendFormat:@" AND category IN (%@)", [nums componentsJoinedByString:@","]];
    }

    BOOL forward = (after != nil);
    BOOL backward = (!forward && before != nil);
    NSString *sql;
    if (forward) {
        sql = [NSString stringWithFormat:
            @"SELECT seq,value FROM app_events WHERE bundle_id=?%@ AND seq>? ORDER BY seq ASC LIMIT ?;", catClause];
    } else if (backward) {
        sql = [NSString stringWithFormat:
            @"SELECT seq,value FROM app_events WHERE bundle_id=?%@ AND seq<? ORDER BY seq DESC LIMIT ?;", catClause];
    } else {
        sql = [NSString stringWithFormat:
            @"SELECT seq,value FROM app_events WHERE bundle_id=?%@ ORDER BY seq DESC LIMIT ?;", catClause];
    }

    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(_database, sql.UTF8String, -1, &stmt, NULL) != SQLITE_OK) return nil;
    int idx = 1;
    sqlite3_bind_text(stmt, idx++, bundle.UTF8String, -1, SQLITE_TRANSIENT);
    if (forward) sqlite3_bind_int64(stmt, idx++, after.longLongValue);
    else if (backward) sqlite3_bind_int64(stmt, idx++, before.longLongValue);
    sqlite3_bind_int64(stmt, idx++, (sqlite3_int64)(limit + 1));

    NSMutableArray<NSDictionary *> *fetched = [NSMutableArray array];
    int rc;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int64_t rowSeq = sqlite3_column_int64(stmt, 0);
        NSData *blob = [NSData dataWithBytes:sqlite3_column_blob(stmt, 1)
                                      length:sqlite3_column_bytes(stmt, 1)];
        id obj = [NSJSONSerialization JSONObjectWithData:blob options:NSJSONReadingMutableContainers error:NULL];
        if (![obj isKindOfClass:NSMutableDictionary.class]) {
            sqlite3_finalize(stmt);
            return nil;
        }
        NSMutableDictionary *dict = obj;
        if (dict[@"seq"]) dict[@"agentSeq"] = dict[@"seq"];
        dict[@"seq"] = @(rowSeq);
        dict[@"appSeq"] = @(rowSeq);
        [fetched addObject:dict];
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) return nil;

    BOOL extra = fetched.count > limit;
    if (extra) [fetched removeObjectsInRange:NSMakeRange(limit, fetched.count - limit)];

    NSArray<NSDictionary *> *events = forward ? fetched : [[fetched reverseObjectEnumerator] allObjects];
    NSDictionary *summary = [self appSummaryForBundle:bundle];
    NSNumber *oldest = events.firstObject[@"seq"] ?: @0;
    NSNumber *latest = events.lastObject[@"seq"] ?: (forward ? after : summary[@"lastSeq"]);
    return @{
        @"ok": @YES,
        @"events": events,
        @"hasOlder": @(forward ? NO : extra),
        @"hasMore": @(forward ? extra : NO),
        @"oldestSeq": oldest,
        @"latestSeq": latest,
        @"next": latest,
        @"summary": summary,
    };
}

- (NSDictionary *)clearEventsForBundle:(NSString *)bundle {
    if (!bundle.length) return nil;
    if (![self execute:"BEGIN IMMEDIATE"]) return nil;
    sqlite3_stmt *stmt = NULL;
    int deleted = 0;
    BOOL ok = sqlite3_prepare_v2(_database, "DELETE FROM app_events WHERE bundle_id=?;", -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_bind_text(stmt, 1, bundle.UTF8String, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_DONE;
    if (ok) deleted = sqlite3_changes(_database);
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (ok) {
        ok = sqlite3_prepare_v2(_database, "DELETE FROM app_stats WHERE bundle_id=?;", -1, &stmt, NULL) == SQLITE_OK &&
            sqlite3_bind_text(stmt, 1, bundle.UTF8String, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
            sqlite3_step(stmt) == SQLITE_DONE;
        sqlite3_finalize(stmt);
    }
    if (ok && [self execute:"COMMIT"]) {
        return @{@"ok": @YES, @"bundleId": bundle, @"deleted": @(deleted)};
    }
    [self execute:"ROLLBACK"];
    return nil;
}
@end
