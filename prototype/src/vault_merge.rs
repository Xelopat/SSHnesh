use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

// Keep a credential and its target together when choosing between revisions.
fn records(vault: &Value, group: &str) -> Result<Map<String, Value>, String> {
    if group == "keys" {
        return vault["keys"]
            .as_object()
            .cloned()
            .ok_or_else(|| "Некорректный список ключей.".into());
    }
    if matches!(group,"accounts"|"groups") && vault.get(group).is_none() {
        return Ok(Map::new());
    }
    let mut result = Map::new();
    for item in vault[group]
        .as_array()
        .ok_or("Некорректный список записей.")?
    {
        let id = item["id"]
            .as_str()
            .ok_or("У записи отсутствует идентификатор.")?;
        let record = json!({"item": item, "password": vault["passwords"].get(id)});
        if result.insert(id.to_owned(), record).is_some() {
            return Err("Повторяющийся идентификатор записи.".into());
        }
    }
    Ok(result)
}

pub(crate) fn merge(
    base: &Value,
    local: &Value,
    remote: &Value,
    mut choose_local: impl FnMut(&str, &str) -> Result<bool, String>,
) -> Result<Value, String> {
    let mut merged = json!({"hosts": [], "accounts": [], "keys": {}, "passwords": {}});
    for group in ["hosts", "accounts", "keys","groups"] {
        if group=="groups" {if [base,local,remote].iter().all(|v|v.get(group).is_none()){continue;}merged[group]=json!([]);}
        let before = records(base, group)?;
        let here = records(local, group)?;
        let there = records(remote, group)?;
        for id in here.keys().chain(there.keys()).collect::<BTreeSet<_>>() {
            let (old, left, right) = (before.get(id), here.get(id), there.get(id));
            if group=="groups" {
                if let (Some(l),Some(r))=(left,right) {
                    if l["item"]["label"]==r["item"]["label"] {
                        let members=|record:Option<&Value>| record.and_then(|v|v["item"]["members"].as_array()).into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect::<BTreeSet<_>>();
                        let (base,local,remote)=(members(old),members(left),members(right));
                        let all=local.union(&remote).filter(|id| !base.contains(*id) || local.contains(*id) && remote.contains(*id)).collect::<Vec<_>>();
                        let mut item=l["item"].clone();item["members"]=json!(all);
                        merged[group].as_array_mut().unwrap().push(item);
                        continue;
                    }
                }
            }
            let selected = if left == right || right == old {
                left
            } else if left == old {
                right
            } else if choose_local(group, id)? {
                left
            } else {
                right
            };
            if let Some(record) = selected {
                if group == "keys" {
                    merged[group][id] = record.clone();
                } else {
                    merged[group]
                        .as_array_mut()
                        .unwrap()
                        .push(record["item"].clone());
                    if !record["password"].is_null() {
                        merged["passwords"][id] = record["password"].clone();
                    }
                }
            }
        }
    }
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_changes_and_delete_edit_conflict() {
        let base = json!({"hosts":[{"id":"a"}],"passwords":{"a":{"secret":"old"}},"keys":{}});
        let mut local = base.clone();
        local["keys"]["new"] = json!({"secret":"test"});
        local["hosts"] = json!([]);
        let mut remote = base.clone();
        remote["passwords"]["a"]["secret"] = json!("changed");
        let merged = merge(&base, &local, &remote, |group, id| {
            assert_eq!((group, id), ("hosts", "a"));
            Ok(false)
        })
        .unwrap();
        assert_eq!(merged["keys"], local["keys"]);
        assert_eq!(merged["hosts"], remote["hosts"]);
        assert_eq!(merged["passwords"], remote["passwords"]);
        assert!(merge(&base, &local, &remote, |_, _| Err("Отмена".into())).is_err());
    }
}
